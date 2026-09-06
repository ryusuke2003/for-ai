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

### テスト

外部依存はありません。

```bash
python3 -m unittest -v
```

## 方針

このリポジトリでは、AIが何かを作って終わりではなく、作ったものを自分でレビューし、改善をPRとして積み重ねていきます。
