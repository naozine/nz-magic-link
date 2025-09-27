# 使用済みのログインリンクで生のJSONが表示される問題への対応計画（#11）

このドキュメントは、魔法リンク（Magic Link）検証時にエラーが発生した場合の UX を改善するための仕様および実装方針をまとめたものです。対象課題は Issue #11「使用済みのログインリンクをクリックしたとき、生のjsonがブラウザに表示される」です。

- 現状: `GET /verify?token=...` にて、検証失敗時は JSON を返却（例: `{"error": "token has already been used"}`）。
- 課題: ブラウザで直接アクセスするユーザーには不親切で、アプリ側での見た目・誘導が困難。
- 目標: 検証失敗時に、指定のエラー用リダイレクト先に遷移し、エラー理由とコードをクエリで判別できるようにする。

関連コード:
- Tokenの検証: `magiclink/internal/token/token.go`
- Verifyハンドラ: `magiclink/handlers/verify.go`

---

## 1. 要件

1. エラー用のリダイレクト先を指定できること。
2. リダイレクト先のページで、エラー理由・エラーコードを機械的に判別可能であること。
3. 後方互換: 設定がない場合は従来通り JSON を返す。

---

## 2. 仕様案

### 2.1 リダイレクト先の指定方法

- VerifyHandler にエラー用リダイレクト URL の引数を追加する。
  - 既存: `func VerifyHandler(tokenManager *token.Manager, sessionManager *session.Manager, redirectURL string)`
  - 変更案: `func VerifyHandler(tokenManager *token.Manager, sessionManager *session.Manager, redirectURL string, errorRedirectURL string)`
- クエリでの上書きを許容（任意）。
  - `error_redirect` クエリが存在する場合、`errorRedirectURL` を一時的に上書きする。
  - 注意: オープンリダイレクト対策として、許可ドメイン/同一オリジンのみに制限（必要に応じて許可リストを導入）。

### 2.2 エラー情報のクエリパラメータ

- リダイレクト時に付与するパラメータ（案）
  - `error`: 機械判別用の短いコード（例: `invalid_token`, `token_expired`, `token_used`, `token_required`, `internal_error`）
  - `error_description`: 人間が読む説明（英語または日本語、既存メッセージをベース）
  - `code`: 数値コード（HTTP に準拠するか、アプリ内コード。まずは HTTP ステータス相当を推奨: 400, 401, 500 など）
  - 例: `https://example.com/error?error=token_used&error_description=token%20has%20already%20been%20used&code=400`

- エンコード: `error_description` は URL エンコードする。

### 2.3 対応エラーの分類

`magiclink/internal/token/token.go` にて発生し得る主な検証エラーは以下の通り。

- トークン未指定: `Token is required`（ハンドラ側） → `error=token_required`, `code=400`
- 無効なトークン: `invalid token` → `error=invalid_token`, `code=400`
- 期限切れ: `token has expired` → `error=token_expired`, `code=400`
- 使用済み: `token has already been used` → `error=token_used`, `code=400`
- 内部エラー: 例 `failed to get token: ...` / `failed to mark token as used: ...` → `error=internal_error`, `code=500`

ハンドラ側で `err.Error()` を判定し、上記のコードにマッピングする薄いヘルパ関数を用意する。

### 2.4 後方互換と分岐

- `errorRedirectURL` が空文字かつ `error_redirect` も未指定 → 現行通り JSON を返す。
- それ以外 → リダイレクト。

### 2.5 成功時の挙動（参考）

- 既存の成功時リダイレクト `redirectURL` は据え置き。クエリ `redirect` による上書きは Logout で既に実装済みだが、Verify にも導入するかは別検討（今回のスコープ外）。

---

## 3. 実装方針（概要）

1. VerifyHandler の関数シグネチャを変更して `errorRedirectURL string` を追加。
2. ハンドラ内部で検証エラー時の分岐を変更。
   - 既存: `return c.JSON(status, ErrorResponse{ Error: ... })`
   - 変更: `errorRedirectURL`（または `error_redirect`）があれば 302 リダイレクトへ切り替え。
3. エラー文字列をコードへマッピングする関数を追加（`handlers` パッケージ内）。
4. リダイレクト URL 組み立て時に、既存のクエリがあれば保持しつつ `error`, `error_description`, `code` を上書き追加。
5. セキュリティ対策（重要）
   - `error_redirect` による上書きを許す場合は、最低限 `http(s)` スキーム限定、オープンリダイレクト対策として許可ドメインの制御を検討。
   - ログにエラーコードを記録（PII を含まない範囲）。

---

## 4. 例

- 使用済みトークンでアクセス: `GET /verify?token=...&error_redirect=https://app.example.com/login/error`
  - リダイレクト先: `https://app.example.com/login/error?error=token_used&error_description=token%20has%20already%20been%20used&code=400`

- トークン未指定でアクセス（サーバ設定で `errorRedirectURL=https://app.example.com/error`）
  - リダイレクト先: `https://app.example.com/error?error=token_required&error_description=Token%20is%20required&code=400`

- 設定がない場合
  - 従来通り JSON: `{ "error": "token has already been used" }`

---

## 5. マイグレーション・利用方法

- アプリ側で VerifyHandler を組み込む際、エラー用リダイレクト URL を渡す。
  - 例: `e.GET("/verify", handlers.VerifyHandler(tokenMgr, sessionMgr, successRedirect, errorRedirect))`
- クライアント（フロントエンド）は、エラーページで `location.search` を解析して UI 表示と誘導を行う。
- 既存の呼び出しは、追加引数に空文字を渡せば現行挙動維持。

---

## 6. テスト計画

- ユニットテスト（ハンドラ）
  - トークン未指定時: JSON / リダイレクト両モード
  - 無効トークン: JSON / リダイレクト
  - 期限切れ: JSON / リダイレクト
  - 使用済み: JSON / リダイレクト
  - 内部エラー（DB 失敗をモック）: JSON / リダイレクト
  - `error_redirect` 上書きの優先順位と URL 検証

- 結合テスト（サンプルアプリ）
  - メールからリンクを踏んだときの失敗/成功の遷移

- セキュリティ
  - オープンリダイレクト抑止の挙動（許可ドメイン外は無効化→JSON 返却 or 既定の errorRedirectURL を使用）

---

## 7. ロールアウトとドキュメント

- README に「エラー時リダイレクトの使い方」を追記。
- 破壊的変更の有無: VerifyHandler のシグネチャ変更は軽微な破壊的変更に該当。メジャーアップデートでなくてもリリースノートに明記し、移行方法（引数追加）を案内。
- examples/simple などのサンプルも追随（任意）。

---

## 8. 簡易タスク一覧

- [ ] VerifyHandler に `errorRedirectURL` を追加し、エラー時のリダイレクト分岐を実装
- [ ] エラー→コードのマッピング関数を追加
- [ ] `error_redirect` クエリ上書き（任意、実装するなら URL 検証を含む）
- [ ] テスト追加
- [ ] README / examples 更新

---

## 参考（現状コードの該当行）

- `magiclink/handlers/verify.go`
  - トークン未指定: `return c.JSON(http.StatusBadRequest, ErrorResponse{ Error: "Token is required" })`
  - 検証エラー: `return c.JSON(http.StatusBadRequest, ErrorResponse{ Error: err.Error() })`
- `magiclink/internal/token/token.go`
  - `invalid token`, `token has expired`, `token has already been used` の返却箇所が存在
