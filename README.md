# zenn-content

[Zenn](https://zenn.dev) の記事を管理するリポジトリ。GitHub連携でデプロイする。

## 使い方

```bash
npm install          # 初回のみ（zenn-cli を入れる）
npx zenn preview     # http://localhost:8000 でローカルプレビュー
npx zenn new:article # 新しい記事の雛形を作る
```

## 公開フロー

1. `articles/<slug>.md` を書く（`published: false` は下書き）
2. push すると Zenn に下書きとして同期される（自分だけ閲覧可）
3. 内容を確認し、`published: true` にして push すると公開される

## 記事一覧

- `articles/aws-waf-managed-count-label.md` — AWS WAF マネージドルールを Count×ラベルマッチで段階移行する（最小再現コード: [waf-count-label-cdk](https://github.com/wistixsub/waf-count-label-cdk)）
