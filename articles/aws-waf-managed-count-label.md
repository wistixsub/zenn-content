---
title: "AWS WAFのマネージドルールを「いきなりBlock」しないーCountモード×ラベルマッチで段階移行する"
emoji: "🛡️"
type: "tech"
topics: ["aws", "waf", "cdk", "security", "typescript"]
published: true
---

## はじめに

先日、ある案件の構築中環境で「WAFにリクエストがブロックされてしまう」事象の調査を担当する機会がありました。原因を追っていくと、AWSマネージドルールのうちの1つが正規のリクエストを**誤検知**していた、というオチでした。

WAFを触ったことがある方なら、一度は通る道かもしれません。「攻撃した覚えはないのに403」「昨日まで動いていた機能が急に弾かれる」—マネージドルールは強力な反面、こうした"巻き込み事故"が起きます。

このときは、優先度の都合でまず該当ルールを `Count`（検知するがブロックはしない）に倒して急場をしのぎました。ただ `Count` のままでは当然守れてはいないので、「**どう安全に `Block` へ戻していくか**」を改めて整理する必要がありました。

本記事は、その調査の過程で学んだこと（特に **ラベル** まわりの仕組み）と、`Count` から `Block` へ段階的に切り替えていくために考えたことを、最小再現の CDK コードつきで記録したものです。同じように「いきなり Block は怖い、でも Count のままも気持ち悪い」と感じている方の参考になれば嬉しいです。

## この記事の要点（先に結論）

- AWSマネージドルールグループを**いきなり `Block` で有効化**すると、正規のトラフィックを巻き込んで事故ります。
- かといって全体を `Count` にしたままだと、いつまでも守れません。
- 解決策は **「マネージドルールは Count に倒し、付与される *ラベル* を自前ルール `LabelMatchStatement`で拾って、誤検知を除外したうえで Block する」** という二段構えです。
- これにより「ルール単位・パス単位で、安全を確認できたものから順にBlockへ昇格させる」運用ができます。
- 本記事は最小再現の CDK（TypeScript / `CfnWebACL`）付きです。

---

## 1. なぜ「いきなり Block」が事故るのか

`AWSManagedRulesCommonRuleSet`（CRS）のようなマネージドルールは強力ですが、正規トラフィックを攻撃と誤判定することがあります。現場で実際に踏むのはこんなケースです：

- リッチエディタや問い合わせフォームで `<script>` を含む正当な入力 → `CrossSiteScripting_BODY` で 403
- 数MBのファイルアップロード → `SizeRestrictions_BODY`（デフォルト8KB）で 403
- JMeter / Postman / curl の動作確認 → `NoUserAgent_HEADER` で 403
- GraphQL のイントロスペクション → `SQLi_QUERYARGUMENTS` に部分一致して 403

`Block` で投入すると、これらが**本番でいきなり起きます**。WAF導入直後に問い合わせが止まって慌てる、という事態が考えられるパターンです。

:::message
**前提：マネージドルールは「ルールの詰め合わせ」**
`AWSManagedRulesCommonRuleSet`（CRS）は単一のルールではなく、AWSが管理する**ルールグループ**です。中に `CrossSiteScripting_BODY`・`SizeRestrictions_BODY`・`NoUserAgent_HEADER` など複数の**個別ルール**が入っています。各ルールが「何を検査し」「どんなラベルを付け」「WCUをいくつ消費するか」は、[AWS公式の "AWS Managed Rules rule groups list"](https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-list.html) に全件公開されています。
さらにルールグループには**バージョン**があり、更新で個別ルールやラベルが増減することがあります。後述の `Count`/`Block` 上書きは**個別ルール名**を指定して行うので、バージョンを上げるときはルール名・ラベルが変わっていないか確認しておくと安全です。
:::

---

## 2. ポイントは「Count に倒してもラベルは付く」

ここが本記事の中心です。

マネージドルールグループの個別ルールを **`RuleActionOverride` で `Count` に上書き**すると、そのルールは **リクエストをブロックしませんが、ラベルは付与し続けます**。

付与されたラベルは、CloudWatch Logs などに送られる WAF のログに記録されます。Count に倒したルールが合致したとき、ログ（抜粋・一部フィールドは省略）はこんな形です：

```json
{
  "timestamp": 1718450000000,
  "action": "ALLOW",
  "terminatingRuleId": "Default_Action",
  "terminatingRuleType": "REGULAR",
  "ruleGroupList": [
    {
      "ruleGroupId": "AWS#AWSManagedRulesCommonRuleSet",
      "terminatingRule": null,
      "nonTerminatingMatchingRules": [
        {
          "ruleId": "CrossSiteScripting_BODY",
          "action": "COUNT",
          "ruleMatchDetails": [
            { "conditionType": "XSS", "location": "BODY", "matchedData": ["<", "script", ">"] }
          ]
        }
      ],
      "excludedRules": null
    }
  ],
  "httpRequest": {
    "clientIp": "203.0.113.50",
    "country": "JP",
    "uri": "/admin/posts",
    "httpMethod": "POST"
  },
  "labels": [
    // ↓↓↓【ここが本題】この値を後続ルール（Has a label）で拾う ↓↓↓
    { "name": "awswaf:managed:aws:core-rule-set:CrossSiteScripting_Body" }
  ]
}
```

このログでいちばん重要なのは、末尾の **`labels` 配列**です：

- **`labels` 配列に付いた `awswaf:managed:aws:core-rule-set:CrossSiteScripting_Body` こそ、このあと「ラベルマッチ（Has a label）」で拾う対象**です。2-2 で作る自前ルールは、この文字列を `LabelMatchStatement` で参照してブロック判定します。Logs Insights で集計するのも同じこの値です。
- 最終的な `action` は `ALLOW`。Count は終端しないので、リクエストはデフォルトの Allow まで流れています（＝ブロックされていない）。
- 合致した `CrossSiteScripting_BODY` は `ruleGroupList` の `nonTerminatingMatchingRules` に `action: COUNT` として記録されます。「検知はした」痕跡がここに残ります。

他のルールも同様に、`...:NoUserAgent_Header` や `awswaf:managed:aws:sql-database:SQLi_QueryArguments` のような文字列で `labels` に残ります。

つまり Count モードは「検知はするが行動はしない」状態であり、**そのラベルを後続の自前ルールで拾えます**。なぜ Count だと拾えるのか、ラベルの仕組みから順に押さえていきます。

### 2-1. なぜ Count だとラベルを拾えるのか — ラベルの仕組みと評価順序

ラベルは、**ルールがリクエストに合致したときに、そのリクエストへ付けられるメタデータ**（タグのようなもの）です。AWSマネージドルールは、合致したリクエストに「どのルールが当たったか」を示すラベルを付けます。

1リクエストに対する Web ACL の評価は、ざっくりこの順序で進みます：

1. Web ACL 内のルールを **priority 順**に評価します
2. あるルールが合致したら、**まずそのルールのラベルが付きます**
3. 続けて**そのルールのアクション**（Allow / Block / Count）が適用されます
4. アクションが**終端（Allow / Block）なら、そこで Web ACL の評価は終了**します。非終端（Count）なら**次の priority のルールへ進みます**

公式の記述です：

> A label is metadata added to a web request by a rule **when the rule matches** the request. Once added, a label remains available until the web ACL evaluation ends. You can access labels in rules that run **later** in the evaluation by using a label match statement.
>
> After a match is found, AWS WAF **continues** evaluating the request **if the rule action doesn't terminate** the evaluation. ... change the actions for your existing rules to **Count** and configure them to add labels to matching requests.

つまり、**ラベルは「合致した瞬間」に付きますが、それを使えるのは"後ろの" priority のルールだけ**です。ここから Count の必要性が出てきます：

- マネージドルールを素の **`Block`** のまま使うと、合致した瞬間に**終端して評価が止まります**。ラベルは付きますが、それを拾う後続ルールが**そもそも走りません**。
- マネージドルールを **`Count`（非終端）** に倒すと、**ラベルは付いたまま評価が続行**します。だから後ろに置いた自前ルールがそのラベルを拾えます。

「Count に倒すとラベルが拾える」のカラクリはこれです。`Count` は「検知するが**止めない**」アクションなので、**ラベルだけ残して判断を後続ルールにバトンタッチ**できる、というわけです。

### 2-2. ラベルを「Has a label」で拾う旨味

付いたラベルは、自前のカスタムルールで **「Has a label」（API/CDK では `LabelMatchStatement`）** を使って拾えます。コンソールなら、ルール作成の検査対象で「Has a label」を選び、ラベル名（`awswaf:managed:aws:core-rule-set:CrossSiteScripting_Body` など）を指定するだけです。

何が嬉しいかというと、**「マネージドルールが検知した」という結果に、自分の条件とアクションを後から重ねられる**点です：

- **誤検知の除外**：「XSSラベルが付いている **かつ** `/admin/posts` 以外 **かつ** 社内IP以外」のときだけ Block（本記事の本題）
- **複数検知の組み合わせ**：「XSSラベル **かつ** Bot Control のラベル」のように、複数のマネージド検知を AND して初めて Block する高度な判定
- **検知のグルーピング／別アクション**：複数ルールのラベルを1本で拾い、Block ではなくカスタムレスポンスを返す・`Count` のまま監視だけ続ける、など
- **ロジックの再利用**：共通条件を「ラベルを付けるだけのルール」に切り出し、後続の複数ルールはラベルの有無だけ見る（同じ条件の二重メンテを防ぐ）

要は、**マネージドルールの「検知」と、最終的な「アクション」を切り離せる**のがラベルの本質的な価値です。当たり判定はAWSのマネージドルールに任せ、止めるかどうかの判断は自分のルールで握る、という分業ができます。

> **地味な罠：ルール名とラベル名でケース（大文字小文字）が違います**
> ルール名はサフィックスが大文字（`CrossSiteScripting_BODY` / `NoUserAgent_HEADER`）ですが、付与されるラベルは混在ケース（`...core-rule-set:CrossSiteScripting_Body` / `...:NoUserAgent_Header`）です。
> - `ruleActionOverrides` に書くのは**ルール名**（大文字サフィックス）
> - `labelMatchStatement` に書くのは**ラベル名**（混在ケース）
> ルール名を間違えると `cdk synth` は通るのに**デプロイ時に失敗します**。さらに厄介なのはラベル側で、ラベルはただの文字列なので**typoしてもエラーにならず、一生マッチしないルール**ができあがります。公式ドキュメントの表で両方を必ず確認してください。
>
> しかも**このケース変換のルールはマネージドグループ間で一貫していません**。同じ `QUERYSTRING` というサフィックスでも、
> - Core rule set：`SizeRestrictions_QUERYSTRING`（ルール名）→ ラベル `...core-rule-set:SizeRestrictions_QueryString`（混在ケースに変換される）
> - WordPress：`WordPressExploitableCommands_QUERYSTRING`（ルール名）→ ラベル `...wordpress-app:WordPressExploitableCommands_QUERYSTRING`（**大文字のまま**）
>
> となります。「サフィックスは混在ケースに直る」という思い込みも通用しません。**グループごとに公式表のラベル文字列をコピペするのが唯一の正解です。**

この性質を使うと、こういう流れが組めます：

```
[マネージドルール群] action = Count（ブロックしない・ラベルだけ付ける）
        ↓ ラベル付与
[自前ルール] LabelMatchStatement でラベルを拾う
        ↓
   誤検知の条件（特定パス・特定IP）を AND NOT で除外
        ↓
   残ったものだけ Block
```

ルールの**評価順（priority）**が重要で、マネージドルール群を先に評価してラベルを付け、その後ろの priority に自前のラベルマッチルールを置きます。

---

## 3. 段階移行のステップ

段階移行には、**どちらから入るか**で2つのやり方があります。本番稼働中かどうか・ブロックされたときの影響の大きさで選びます。

### 3-1. パターンA：Count から始める（安全側・新規導入向き）

いきなりブロックしたくない場合の王道です。

1. **全マネージドルールを Count で投入**（`OverrideAction: Count` をグループ全体に、または `RuleActionOverride` を個別ルールに）
2. **CloudWatch Logs Insights でラベル別に集計**し、どのルールがどれだけ発火しているか・誤検知かを切り分けます
3. **安全と判断できたルールから**、ラベルマッチルールで Block へ昇格（誤検知パスは `AND NOT` で除外）
4. すべて安全確認できたら、マネージドルール側の override を外して素直に Block にしても構いません

- **メリット**：正規トラフィックを一度もブロックしない。本番稼働中のサービスに後から WAF を入れるときでも安全です。
- **デメリット**：「まだ守れていない期間」が発生します。全ルールを見終わるまで時間がかかります。

### 3-2. パターンB：Block から始めて、誤検知だけ Count に落とす（効率側）

「ブロックされても影響が小さい」状況（構築中・リリース前の環境、社内向けなど）なら、こちらの方が速いです。マネージドルールは明らかに異常なリクエストでなければ基本は通るので、多くのケースでは**少数の誤検知だけ**が問題になります。最初から守った状態で走り、出てきた誤検知にだけ対処する、という考え方です。

1. **まずマネージドルールを Block で適用**してしまう（最初から守られている状態）
2. **誤検知でブロックされたものを Logs Insights / Sampled Requests で特定**する
3. **該当する個別ルールだけ Count に落とす**（必要なら、特定パス・IPだけ通す自前ルールを足して誤検知を回避）
4. 原因に対処できたら、その個別ルールを **Block に戻す**

- **メリット**：最初から守られている。対処すべきは「実際に出た誤検知」だけなので、空振りの調査が減って効率的です。
- **デメリット**：誤検知が出た瞬間、正規リクエストがブロックされます。本番稼働中のサービスでは事故になり得るので、**影響を許容できる環境に限ります**。

### どちらを選ぶか

- **本番稼働中・ブロックの影響が大きい** → パターンA（Count から）
- **構築中・リリース前・影響が小さい** → パターンB（Block から）

どちらにしても、**ラベルで「どのルールが・どこで」発火したかを切り分け、ルール単位・パス単位で Count↔Block を出し入れする**という仕組みは共通です。「グループ丸ごと Block / Count」ではなく、粒度を細かく扱えるのがポイントです。

### 3-3. 集計に使う Logs Insights クエリ

ラベルは WAF ログの `labels` 配列に入ります。発火ラベルを数える例です：

```
fields @timestamp, httpRequest.uri
| parse @message '"name":"*"' as label
| filter ispresent(label)
| stats count() as hits by label, httpRequest.uri
| sort hits desc
| limit 50
```

「このラベルは `/admin/posts` でしか発火していない＝リッチエディタの誤検知だな」と当たりをつけて、除外条件を決めます。

---

## 4. 最小再現 CDK（TypeScript）

`aws-cdk-lib` の `aws_wafv2.CfnWebACL`（L1）で組みます。WAFv2 は L2 が薄いので L1 が素直です。動く一式は [wistixsub/waf-count-label-cdk](https://github.com/wistixsub/waf-count-label-cdk) に置いてあります（`npm install && npx cdk synth` で CloudFormation を生成できます）。

```ts
import { Stack, StackProps } from "aws-cdk-lib";
import { Construct } from "constructs";
import { CfnWebACL, CfnIPSet } from "aws-cdk-lib/aws-wafv2";

export class WafCountLabelStack extends Stack {
  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);

    // 負荷試験・社内動作確認などをバイパスする許可IP（誤検知除外に使う）
    const allowIpSet = new CfnIPSet(this, "AllowIpSet", {
      addresses: ["203.0.113.10/32"], // ← 自社の固定IPに置き換え
      ipAddressVersion: "IPV4",
      scope: "REGIONAL", // CloudFront に付けるなら "CLOUDFRONT"（us-east-1 必須）
    });

    new CfnWebACL(this, "WebAcl", {
      defaultAction: { allow: {} },
      scope: "REGIONAL",
      visibilityConfig: {
        cloudWatchMetricsEnabled: true,
        metricName: "webacl",
        sampledRequestsEnabled: true,
      },
      rules: [
        // (1) マネージドルール群: まずは Count に倒す（ラベルは付く）
        {
          name: "AWS-AWSManagedRulesCommonRuleSet",
          priority: 10,
          // グループ全体を Count にする場合は overrideAction: { count: {} }
          // ここでは「特定ルールだけ Count、それ以外は素のまま」にしたいので none + ruleActionOverrides
          overrideAction: { none: {} },
          statement: {
            managedRuleGroupStatement: {
              vendorName: "AWS",
              name: "AWSManagedRulesCommonRuleSet",
              // 誤検知しやすい個別ルールだけ Count に上書き（ラベルは付与され続ける）
              ruleActionOverrides: [
                // ★ここは「ルール名」＝大文字サフィックス（ラベル名とケースが違う点に注意）
                { name: "CrossSiteScripting_BODY", actionToUse: { count: {} } },
                { name: "SizeRestrictions_BODY", actionToUse: { count: {} } },
                { name: "NoUserAgent_HEADER", actionToUse: { count: {} } },
              ],
            },
          },
          visibilityConfig: {
            cloudWatchMetricsEnabled: true,
            metricName: "CommonRuleSet",
            sampledRequestsEnabled: true,
          },
        },

        // (2) ラベルマッチで「昇格」: Count に倒した XSS ラベルを拾い、
        //     誤検知パス(/admin/posts)と許可IPを除外してから Block する
        {
          name: "Block-XSS-Except-Editor",
          priority: 20,
          action: { block: {} },
          statement: {
            andStatement: {
              statements: [
                // CRS が付けた XSS ラベル
                {
                  labelMatchStatement: {
                    scope: "LABEL",
                    key: "awswaf:managed:aws:core-rule-set:CrossSiteScripting_Body",
                  },
                },
                // リッチエディタのパスは除外（正規の <script> 入力を通す）
                {
                  notStatement: {
                    statement: {
                      byteMatchStatement: {
                        fieldToMatch: { uriPath: {} },
                        positionalConstraint: "STARTS_WITH",
                        searchString: "/admin/posts",
                        textTransformations: [{ priority: 0, type: "NONE" }],
                      },
                    },
                  },
                },
                // 社内固定IPも除外
                {
                  notStatement: {
                    statement: {
                      ipSetReferenceStatement: { arn: allowIpSet.attrArn },
                    },
                  },
                },
              ],
            },
          },
          visibilityConfig: {
            cloudWatchMetricsEnabled: true,
            metricName: "BlockXssExceptEditor",
            sampledRequestsEnabled: true,
          },
        },
      ],
    });
  }
}
```

### コードの読みどころ

- **(1)** マネージドルール群は `overrideAction: { none: {} }`（＝グループとしては素の動作）にしつつ、**`ruleActionOverrides` で誤検知しやすい個別ルールだけ `count` に上書き**します。Count にしてもラベルは付きます。
- **(2)** `labelMatchStatement` で (1) が付けたラベルを拾い、**`notStatement` で誤検知パス・許可IPを除外**してから `block` します。これが「安全を確認できたものだけ Block へ昇格」の正体です。
- priority は **マネージドルール(10) → ラベルマッチ(20)** の順です。先にラベルを付けないと拾えません。

> 補足：グループ *全体* を Count にしたいだけなら `overrideAction: { count: {} }` で済みます。個別ルール単位で昇格を制御したいときに `ruleActionOverrides` が効きます。

---

## 5. 運用に乗せるときの注意

- **WCU と料金**：マネージドルールグループごとに WCU を消費します（CRS は 700 WCU）。Web ACL あたり 1,500 WCU を超えると追加費用が発生します。投入前に積算しておきましょう。
- **ラベル名はバージョンで変わりうる**：マネージドルールグループのバージョンアップで個別ルール名・ラベルが増減することがあります。**バージョン更新時は再度 Count で様子見**するのが安全です。
- **Sampled Requests / フルログ**：`sampledRequestsEnabled: true` に加え、本気で運用するならログを S3/CloudWatch に出して Insights で継続監視しましょう。
- **除外は「最小スコープ」で**：`notStatement` の除外は広げすぎると穴になります。パス＋IPなど条件を絞りましょう。

---

## まとめ

- マネージドルールは **Count に倒してもラベルは付きます**。これが段階移行の土台です。
- **ラベルマッチ + 除外条件 → Block** で、ルール単位・パス単位に安全確認しながら昇格できます。
- 「いきなり Block で事故る」も「Count のままで守れない」も避けて、上手に・安全に運用していきましょう。
