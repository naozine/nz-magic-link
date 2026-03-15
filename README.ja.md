# Magic Link Authentication for Go/Echo

Go アプリケーション向けの、シンプルで安全なパスワードレス認証ライブラリです。Echo Web フレームワークと統合し、メールによるマジックリンク認証と WebAuthn/Passkey 認証を提供します。

## 特徴

- **パスワードレス認証**: メールでマジックリンクを送信し、安全にログイン
- **WebAuthn/Passkey 対応**: 指紋・顔認証などのパスキー認証（オプション）
- **複数ストレージバックエンド**: SQLite（純Go、CGo不要）と LevelDB
- **インメモリトークンストレージ**: 高同時接続シナリオ向けの高性能モード（オプション）
- **デフォルトでセキュア**: トークンとセッションのセキュリティベストプラクティスを実装
- **レートリミット**: 設定可能なレート制限による不正利用防止
- **カスタマイズ可能**: トークン、セッション、メールの柔軟な設定
- **Echo 統合**: Echo Web アプリケーションへの簡単な統合

## v0.3.0 への移行

v0.3.0 には WebAuthn 実装の破壊的変更が含まれています。**WebAuthn/パスキー機能を使用している場合、クライアント側のコードを更新する必要があります。**

### 破壊的変更

1. **WebAuthn ログイン/登録のレスポンス形式が変更**
   - `POST /webauthn/login/start` と `POST /webauthn/login/discoverable` のレスポンスが `{"options": {"publicKey": {...}}}` 形式に変更（以前のフラット形式 `{"options": {"challenge": ..., "allowCredentials": ...}}` から）
   - `POST /webauthn/register/finish` と `POST /webauthn/login/finish` の `response` フィールドは base64url エンコードされた文字列（`credential.toJSON()` の出力）を期待（バイト配列ではなく）

2. **パスキークレデンシャルの DB スキーマ更新**
   - `passkey_credentials` テーブルに `backup_eligible` と `backup_state` カラムが起動時に自動追加される
   - Backup Eligible フラグを正しく扱うため、既存のパスキーはアップグレード後に再登録を推奨

### 推奨: 組み込みの `webauthn.js` を使用

クライアント側の互換性問題を避ける最も簡単な方法は、ライブラリ組み込みの WebAuthn クライアントスクリプトを使用することです:

```html
<script src="/webauthn/static/webauthn.js"></script>

<input type="email" autocomplete="username webauthn" />

<script>
  // Conditional Mediation: input フォーカス時にパスキーを提案
  MagicLink.conditionalLogin();

  // パスキー登録
  await MagicLink.register(email);

  // メール指定ログイン
  await MagicLink.login(email);

  // Discoverable ログイン（メール不要）
  await MagicLink.loginDiscoverable();
</script>
```

完全な動作例は [examples/webauthn-simple](examples/webauthn-simple) を参照してください。

### 独自の WebAuthn クライアントコードがある場合

ブラウザネイティブの WebAuthn JSON API を使うように更新してください:

```javascript
// 変更前（v0.2.x）
options.challenge = base64urlToBuffer(options.challenge);
const assertion = await navigator.credentials.get({ publicKey: options });
const body = { rawId: bufferToBase64url(assertion.rawId), ... };

// 変更後（v0.3.0）
const assertion = await navigator.credentials.get({
    publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(startResp.options.publicKey)
});
const body = { response: assertion.toJSON() };
```

## インストール

```bash
go get github.com/naozine/nz-magic-link
```

## クイックスタート

リポジトリ内の以下のディレクトリに動作するサンプルがあります:

### シンプルな例 ([examples/simple](examples/simple))

- Echo サーバーでのマジックリンク認証のセットアップ
- メール送信用の SMTP 設定
- 公開ルートと保護されたルートの作成
- ログイン・ダッシュボードページの HTML テンプレート
- 環境変数による設定

### メールテスト例 ([examples/email-test](examples/email-test))

- To、件名、本文のフォーム入力によるメール送信テスト
- カスタムメールテンプレートの生成
- トークン生成とマジックリンクの作成
- 開発モードでのメール送信バイパス

### WebAuthn 例 ([examples/webauthn-simple](examples/webauthn-simple))

- パスキーの登録・ログインフロー
- Discoverable Credential のサポート
- マジックリンク + パスキーの併用

### 基本的な使い方

1. Echo インスタンスを作成
2. SMTP 設定で MagicLink インスタンスを構成
3. 認証ハンドラを登録
4. 認証ミドルウェアで保護されたルートを作成
5. サーバーを起動

## 設定

`Config` 構造体で設定できます:

```go
config := magiclink.DefaultConfig()
```

### データベース設定

- `DatabasePath`: データベースファイルのパス（デフォルト: `"magiclink.db"`）
- `DatabaseType`: ストレージバックエンド — `"sqlite"` または `"leveldb"`（デフォルト: `"sqlite"`）
- `DatabaseOptions`: バックエンド固有のオプション `map[string]string`（デフォルト: `{}`）
  - SQLite: `journal_mode`, `synchronous`, `cache_size`, `temp_store`
  - LevelDB: `block_cache_capacity`, `write_buffer`, `compaction_table_size`

### メール設定

- `SMTPHost`: SMTP サーバーのホスト名
- `SMTPPort`: SMTP サーバーのポート（デフォルト: `587`）
- `SMTPUsername`: SMTP 認証ユーザー名
- `SMTPPassword`: SMTP 認証パスワード
- `SMTPFrom`: 送信元メールアドレス
- `SMTPFromName`: 送信元の表示名
- `SMTPUseTLS`: 接続開始時から TLS を使用 — ポート 465 の Implicit TLS（デフォルト: `false`）
- `SMTPUseSTARTTLS`: STARTTLS を使用 — ポート 587 で TLS にアップグレード（デフォルト: `true`）
- `SMTPSkipVerify`: TLS 証明書の検証をスキップ（デフォルト: `false`）
- `EmailTemplate`: カスタムメールテンプレート（任意）
- `EmailSubject`: メールの件名（デフォルト: `"Your Magic Link for Authentication"`）
- `ServerAddr`: マジックリンク構築用のサーバーアドレス（デフォルト: `"http://localhost:8080"`）

### トークン設定

- `TokenExpiry`: トークンの有効期間（デフォルト: `30 * time.Minute`）
- `UseInMemoryTokens`: トークンをデータベースではなくメモリに保存（デフォルト: `true`）。セッションは引き続きデータベースを使用。詳細は[インメモリトークンストレージ](#インメモリトークンストレージ)を参照。

### セッション設定

- `SessionExpiry`: セッションの有効期間（デフォルト: `7 * 24 * time.Hour`）
- `CookieName`: セッション Cookie の名前（デフォルト: `"session"`）
- `CookieSecure`: Cookie の Secure フラグ（デフォルト: `true`）
- `CookieHTTPOnly`: Cookie の HttpOnly フラグ（デフォルト: `true`）
- `CookieSameSite`: Cookie の SameSite ポリシー（デフォルト: `"lax"`）
- `CookieDomain`: Cookie のドメイン（任意）
- `CookiePath`: Cookie のパス（デフォルト: `"/"`）

### URL 設定

- `LoginURL`: ログインエンドポイントの URL（デフォルト: `"/auth/login"`）
- `VerifyURL`: 検証エンドポイントの URL（デフォルト: `"/auth/verify"`）
- `RedirectURL`: 検証成功後のリダイレクト先（デフォルト: `"/"`）
- `LogoutRedirectURL`: ログアウト成功後のリダイレクト先（デフォルト: `"/"`）
- `ErrorRedirectURL`: 検証エラー時のリダイレクト先（任意）

### レートリミット

- `MaxLoginAttempts`: 時間窓内のメールあたりの最大ログイン試行回数（デフォルト: `5`）
- `RateLimitWindow`: レートリミットの時間窓（デフォルト: `15 * time.Minute`）
- `DisableRateLimiting`: IP ベースおよびメール別のレートリミットをすべて無効化（デフォルト: `false`）。テストやベンチマーク用。

### ログインのカスタマイズ

- `LoginSuccessMessage`: ログインリクエスト成功時のメッセージ（デフォルト: `"Magic link sent to your email"`）
- `AllowLogin`: ログイン可否を制御するコールバック関数 `func(c echo.Context, email string) error`。エラーを返すとログインを拒否。

### 開発用設定

- `DevBypassEmailFilePath`: メール送信をバイパスするメールアドレスまたはワイルドカードパターンのファイルパス。以下の形式に対応:
  - 完全一致のメールアドレス（例: `test@example.com`）
  - ワイルドカードパターン `*`, `?`, `[`（例: `*@test.com`, `loadtest-*@example.com`）
  - `#` で始まる行はコメントとして無視

  該当するメールアドレスがマジックリンクをリクエストすると、メール送信の代わりにレスポンスに `magic_link` としてリンクが返されます。

### WebAuthn/Passkey 設定

- `WebAuthnEnabled`: WebAuthn/Passkey を有効化（デフォルト: `false`）
- `WebAuthnRPID`: Relying Party ID、通常はドメイン（デフォルト: `"localhost"`）
- `WebAuthnRPName`: Relying Party の表示名（デフォルト: `"nz-magic-link"`）
- `WebAuthnAllowedOrigins`: 許可するオリジン（デフォルト: `["http://localhost:8080"]`）
- `WebAuthnChallengeTTL`: チャレンジの有効期間（デフォルト: `5 * time.Minute`）
- `WebAuthnTimeout`: クライアント側のタイムアウト（デフォルト: `60 * time.Second`）
- `WebAuthnUserVerification`: ユーザー認証要件 — `"preferred"`, `"required"`, `"discouraged"`（デフォルト: `"preferred"`）
- `WebAuthnRequireResidentKey`: Discoverable Credential を要求（デフォルト: `true`）
- `WebAuthnRedirectURL`: WebAuthn ログイン成功後のリダイレクト先（デフォルト: `"/dashboard"`）

## API リファレンス

### インスタンスの作成

```go
ml, err := magiclink.New(config)
```

既存の `*sql.DB` 接続を使用する場合（SQLite のみ）:

```go
ml, err := magiclink.NewWithDB(config, db)
```

### ハンドラの登録

```go
ml.RegisterHandlers(e)
```

以下のエンドポイントが登録されます:

**マジックリンク:**
- `POST /auth/login`: メールアドレスを受け取り、マジックリンクを送信。バイパスリストのメールアドレスの場合、レスポンスに `magic_link` として返却。
- `GET /auth/verify`: マジックリンクのトークンを検証し、セッションを作成
- `POST /auth/logout`: セッションを無効化してログアウト。`redirect` クエリパラメータでリダイレクト先を指定可能。

**WebAuthn（有効時）:**
- `POST /webauthn/register/start`: パスキー登録の開始
- `POST /webauthn/register/finish`: パスキー登録の完了
- `POST /webauthn/login/start`: パスキー認証の開始
- `POST /webauthn/login/finish`: パスキー認証の完了
- `POST /webauthn/login/discoverable`: Discoverable（ユーザーレス）認証の開始
- `GET /webauthn/static/webauthn.js`: WebAuthn クライアントスクリプトの配信

### 認証ミドルウェア

```go
e.Use(ml.AuthMiddleware())
```

### ユーザー ID の取得

```go
userID, authenticated := ml.GetUserID(c)
```

### ログアウト

```go
ml.Logout(c)
```

### 期限切れトークン・セッションのクリーンアップ

```go
ml.CleanupExpiredTokens()
ml.CleanupExpiredSessions()
```

### クローズ

```go
ml.Close()
```

### カスタムメールテンプレート

`SendMagicLinkWithTemplateAndData` メソッドで、カスタムテンプレートと追加データを使ってメールを送信できます。

#### 基本的な使い方

```go
// BaseTemplateData を埋め込んだカスタムデータ構造体を定義
type CustomEmailData struct {
    magiclink.BaseTemplateData
    UserName string
    OrderID  string
    Amount   float64
}

// カスタムテンプレートを作成
customTemplate := `From: {{.FromName}} <{{.From}}>
To: {{.To}}
Subject: {{.Subject}}
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 8bit

{{.UserName}} 様

ご注文 {{.OrderID}}（¥{{.Amount}}）の処理が完了しました。

以下のリンクをクリックして認証してください:
{{.MagicLink}}

このリンクは {{.ExpiryMinutes}} 分間有効です。

{{.FromName}}`

customData := &CustomEmailData{
    UserName: "山田太郎",
    OrderID:  "ORDER-12345",
    Amount:   9800.00,
}

_, err := ml.EmailSender.SendMagicLinkWithTemplateAndData(
    "user@example.com",           // to
    token,                        // token
    30,                          // expiryMinutes
    "ご注文確認",                   // subject
    customTemplate,              // template
    customData,                  // data
    false,                       // dryRun
)
```

#### 必須構造

カスタムデータ構造体は `magiclink.BaseTemplateData` を埋め込む必要があります:

```go
type YourCustomData struct {
    magiclink.BaseTemplateData  // 必須
    CustomField1 string
    CustomField2 int
}
```

#### 標準テンプレートマクロ

`BaseTemplateData` で自動的に設定されるマクロ:

- `{{.From}}` - 送信元メールアドレス
- `{{.FromName}}` - 送信者名（メールヘッダー用にエンコード済み）
- `{{.FromNameOriginal}}` - 送信者名（エンコードなし）
- `{{.To}}` - 宛先メールアドレス
- `{{.Subject}}` - 件名（メールヘッダー用にエンコード済み）
- `{{.MagicLink}}` - 生成されたマジックリンク URL
- `{{.ExpiryMinutes}}` - トークンの有効期間（分）

#### ドライランモード

`dryRun` を `true` にすると、メールを送信せずにテンプレートの展開結果をプレビューできます:

```go
previewContent, err := ml.EmailSender.SendMagicLinkWithTemplateAndData(
    "user@example.com", token, 30, "件名", customTemplate, customData, true,
)
// previewContent に展開済みのメールテンプレートが格納される
```

## インメモリトークンストレージ

チケット当選発表など、大量のユーザーが同時にログインするシナリオでは、SQLite のシリアライズされた書き込みがボトルネックになります。インメモリトークンストレージを有効にすると、ログインフェーズの DB 書き込みを排除できます:

```go
config := magiclink.DefaultConfig()
config.UseInMemoryTokens = true
```

**動作の仕組み:**
- ログインフェーズ（マジックリンク送信）: トークンをメモリに保存 — DB 書き込みゼロ
- 検証フェーズ（マジックリンクをクリック）: トークンをメモリから読み取り、セッションを DB に保存 — DB 書き込み1回
- セッション、パスキーなどのデータは引き続きデータベースを使用

**トレードオフ:** プロセスが再起動すると、未検証のトークンは失われます。ユーザーはログインボタンを再度クリックするだけで済みます。トークンは短命（デフォルト30分）で使い捨てなので、これは許容範囲です。

## セキュリティ

- トークンは暗号論的に安全（256ビット）で、SHA-256 ハッシュで保存
- セッションは HttpOnly、SameSite フラグ付きのセキュアな Cookie を使用
- セッション ID はハッシュ化して保存
- レートリミットによるブルートフォース攻撃の防止
- トークンは使い捨て（ワンタイム）で、自動的に有効期限切れ
- トークン検証とセッション作成はアトミック（単一トランザクション）

## ライセンス

MIT
