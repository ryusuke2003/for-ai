# for-ai

AIが自由に作り、レビューし、改善していくための実験場。

## 最初の作品: AI Self Review CLI

AIが回答や文章を出す前に、機械的にチェックできる小さなCLIです。

現在チェックするもの:

- 文章量
- 文の数
- 同じ文の重複
- 「たぶん」「probably」などの曖昧表現
- `TODO` / `FIXME` / `要確認` などの未完了マーカー

### 使い方

ファイルを渡す場合:

```bash
python3 reviewer.py answer.txt
```

標準入力から渡す場合:

```bash
echo 'たぶん動きます。 TODO: 要確認' | python3 reviewer.py
```

機械処理しやすいJSONで出す場合:

```bash
python3 reviewer.py --json answer.txt
```

指摘が1件でもあれば終了コード1にする場合:

```bash
python3 reviewer.py --strict answer.txt
```

## Change Risk Scorer

PRの差分を実行せずに読み、変更内容のレビュー優先度を `LOW` / `MEDIUM` / `HIGH` / `CRITICAL` で評価します。

主に次の変更を重く評価します。

- GitHub ActionsやローカルAction
- 依存関係・デプロイ・インフラ関連ファイル
- 認証・権限・Secret周辺のファイル
- テスト削除
- `write` 権限追加、`pull_request_target`、download-and-executeなどの危険度が高い追加行
- 大規模な差分

GitHub Actionsではpull requestごとに自動評価し、`CRITICAL` の変更はCIを失敗させます。レポートには追加されたソースコード自体を表示せず、カテゴリとエスケープ済みファイルパスだけを出します。

## Test Impact Analyzer

PRでソースコードが変わったときに、テスト変更の有無と確認候補のテストファイルをファイル名ベースで整理します。

- ソース変更があるのにテスト変更がない場合を可視化
- `auth.py` と `test_auth.py`、`session.ts` と `session.test.ts` のような対応候補を提示
- リポジトリ内のコード本文は読まず、パスだけを利用
- シンボリックリンクは辿らない
- レポートに表示するパスは制御文字やMarkdown記号をエスケープ
- 現時点では情報提供のみで、テスト未変更だけを理由にCIを失敗させない

GitHub Actionsではpull requestごとに自動分析します。

## Dependency Policy Guard

依存関係manifestをインストールや実行なしで静的に検査し、サプライチェーン上レビューが必要な指定を検出します。

現在の主な対象:

- `package.json`
- `requirements*.txt`
- `pyproject.toml`
- `Cargo.toml`
- `go.mod`

主に、Git/HTTP URLへの直接依存、カスタムPython package index、リポジトリ外のpath依存をブロックします。`*` / `latest` のような浮動バージョン、npmのinstall lifecycle script、ローカルpath依存、lockfileなしのnpm manifestは警告として表示します。

manifestの内容や依存先URLそのものはレポートへ出さず、カテゴリとエスケープ済みファイルパスだけを表示します。GitHub Actionsではpull requestごとに自動検査します。

### テスト

外部依存はありません。

```bash
python3 -m unittest -v
```

GitHub ActionsでもPython 3.12でテストと各種ガードを自動実行します。

## 方針

このリポジトリでは、AIが何かを作って終わりではなく、作ったものを自分でレビューし、改善をPRとして積み重ねていきます。
