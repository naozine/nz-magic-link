# パスキー（WebAuthn/FIDO2）対応計画

作成日: 2025-09-27

このドキュメントは、nz-magic-link にパスキー（Passkey: WebAuthn/FIDO2）を導入するための計画と設計方針をまとめたものです。既存の「メールによる魔法リンク（Magic Link）」認証を維持しつつ、パスキーを追加導入することで、より高い UX（高速・パスワードレス）とセキュリティを両立します。

---

## 1. 背景・目的

- 目的
  - パスワードレス認証の UX をさらに高め、フィッシング耐性の高い WebAuthn を採用する。
  - 既存の Magic Link と共存できる設計により、段階的な導入・ロールアウトを容易にする。
- 想定利用シナリオ
  - 初回はメールリンクでログイン → ダッシュボードで「この端末でパスキーを設定」を案内。
  - 次回以降は「パスキーでログイン」を優先表示。メールログインはフォールバックとして維持。

---

## 2. 用語

- WebAuthn: Web 認証 API。ブラウザと認証器（プラットフォーム/セキュリティキー）を介し公開鍵認証を行う。
- FIDO2: WebAuthn と CTAP2 の総称。
- パスキー: プラットフォーム（OS）やクラウド間で同期される WebAuthn 資格情報のユーザーフレンドリーな名称。
- RP（Relying Party）: 本サービス（このリポジトリを使うアプリ）
- Authenticator: デバイス内生体認証やセキュリティキー（YubiKey 等）

---

## 3. スコープ

- 対応範囲（このフェーズ）
  - WebAuthn 登録（Create/Attestation）と認証（Get/Assertion）のサーバ側エンドポイントとストレージ層を追加。
  - 既存セッション管理に統合（認証成功後は現在のセッション発行フローへ）。
  - サンプル UI（examples/simple）に最小の導線（登録・ログインボタン＋簡易 JS）を追加する設計方針を定義。
- 非スコープ（将来検討）
  - 多要素（メール＋パスキー同時要求）
  - エンタープライズ向けポリシー細分化
  - 複数 RP ID の高度な運用

---

## 4. 設計概要

### 4.1 RP 設定
- rpID: 運用ドメイン（例: example.com）。ローカル開発は localhost で rpID=localhost を使用。
- rpName: 表示名（例: nz-magic-link Sample）。
- origin: https://<rpID> または http://localhost:8080 等、CORS/Origin 検証に使用。

### 4.2 データモデル（ストレージ）
- PasskeyCredential（新規）
  - id: base64url(credentialID) — 主キー
  - user_id: 既存ユーザー識別子（メールを主キーにしている場合は email）
  - public_key: CBOR もしくは raw 公開鍵バイト（実装ライブラリに依存）
  - sign_count: uint32（リプレイ防止）
  - transports: []string（任意）
  - created_at, updated_at
- PasskeyChallenge（新規; 短期保持）
  - id: ランダム UUID
  - user_id（登録時任意/推奨）, type: "attestation"|"assertion"
  - challenge: ランダムバイト（base64url）
  - expires_at
  - request_options_snapshot: フロントへ返した PublicKeyCredentialCreation/RequestOptions の一部（検証補助）

保存先は既存の storage 抽象化に合わせ、sqlite/leveldb 実装へ最小追加する。

### 4.3 API エンドポイント（案）
- POST /webauthn/register/start
  - 入力: { email }（既存ユーザー紐付けのため）
  - 出力: PublicKeyCredentialCreationOptions（JSON）
- POST /webauthn/register/finish
  - 入力: クライアントからの attestationResponse
  - 動作: 署名/オリジン/RPID 検証、公開鍵抽出、Credential 保存
  - 出力: 成功可否
- POST /webauthn/login/start
  - 入力: { email }（ユーザー探索用; discoverable credentials を優先する場合は省略可）
  - 出力: PublicKeyCredentialRequestOptions（JSON）
- POST /webauthn/login/finish
  - 入力: assertionResponse
  - 動作: 署名検証、signCount 更新、セッション発行（既存フロー）
  - 出力: 成功可否 or リダイレクト

注: CORS/CSRF を考慮し、ブラウザ発呼限定であれば SameSite/HTTPS 運用を前提にする。

### 4.4 既存フローとの統合
- セッション: 認証成功後は handlers/verify.go 同様に session.Manager でクッキー発行。
- 併用: ログイン画面に「メールでログイン」「パスキーでログイン」を併記。
- 初回導入: メールログイン成功後に登録ボタンを提示し、自然な移行を促す。

---

## 5. フロントエンド方針（サンプル）

サンプル用途として examples/simple に最小の JS を追加する設計を定義（詳細実装は別 PR）。

- 登録フロー
  1) email を送信 → /webauthn/register/start
  2) 返却された options を navigator.credentials.create に渡す
  3) 得られた attestation を /webauthn/register/finish へ POST
- ログインフロー
  1) （discoverable 対応なら email 入力省略可）/webauthn/login/start
  2) options を navigator.credentials.get に渡す
  3) assertion を /webauthn/login/finish へ POST → セッションセット → リダイレクト

ユーザー識別子（user.id, user.name, user.displayName）には、既存の email ベースを踏襲。user.id は stable なバイト列（例: email のハッシュ）を使用。

---

## 6. セキュリティ設計

- Origin/RP ID 検証: サーバ側で request.origin と rpID の整合を検証。
- Challenge 一意性と期限: start で生成、短期で失効（例: 5 分）。使い回し禁止。
- Sign Count: assertion 検証時に増加チェック。巻き戻り検知で警告/ブロック。
- Attestation: 初期は none/basic に限定し、AAGUID/Trust Store 検証は将来拡張。
- 送受信データのエンコード: base64url（padding 無し）統一。
- 盗難・移行: 端末紛失時の無効化フロー（管理 UI で Credential を無効化）を将来計画。
- ログ: 機密データ（鍵素材/生体情報）は記録しない。ID とエラーコード中心。

---

## 7. 互換性とフォールバック

- 既存の Magic Link は継続提供。パスキー非対応ブラウザや端末では従来通りログイン可能。
- UI 上で環境判定（PublicKeyCredential in window）によりボタン表示を切替。

---

## 8. 実装タスク（チェックリスト）

- [ ] ストレージ層拡張
  - [ ] interface 追加: PasskeyCredential/Challenge の CRUD
  - [ ] sqlite 実装
  - [ ] leveldb 実装
- [ ] WebAuthn サービス層
  - [ ] RP 設定構造体（rpID, rpName, origins）
  - [ ] チャレンジ生成/保存/検証
  - [ ] Attestation/Assertion 検証（ライブラリ選定もしくは実装）
- [ ] ハンドラ追加（/webauthn/*）
  - [ ] start/finish のリクエスト/レスポンス定義
  - [ ] セッション発行（成功時）
  - [ ] エラーレスポンスとログ整理
- [ ] サンプル UI（examples/simple）
  - [ ] 登録/ログインボタンと最小 JS
  - [ ] 成功/失敗の表示
- [ ] 設定項目追加
  - [ ] Config に rpID, rpName, AllowedOrigins
  - [ ] README 更新
- [ ] テスト
  - [ ] 単体: チャレンジ、検証、signCount
  - [ ] 結合: start→finish の往復
  - [ ] セキュリティ: 不正オリジン、期限切れ、signCount 巻き戻り

---

## 9. ライブラリ選定（Go）

最小実装を優先しつつ、信頼性の高いライブラリ検討。

- 候補
  - github.com/duo-labs/webauthn (メジャー)
  - github.com/go-webauthn/webauthn (フォーク/後継傾向)
- 方針
  - まず duo-labs か go-webauthn のどちらかを採用し、抽象化層を薄く設けて将来差し替えを容易に。

---

## 10. 設定と環境

- Config 追加案（magiclink.Config）
  - RP 設定: WebAuthnRPID string, WebAuthnRPName string, WebAuthnAllowedOrigins []string
  - 時限: WebAuthnChallengeTTL time.Duration（既定 5m）
- .env サンプルへの追記と README の利用方法を更新。

---

## 11. ルーティング統合案

- magiclink パッケージに WebAuthn ハンドラ登録用のヘルパーを追加（任意）
  - e.POST("/webauthn/register/start", handlers.WebAuthnRegisterStart(...))
  - e.POST("/webauthn/register/finish", handlers.WebAuthnRegisterFinish(...))
  - e.POST("/webauthn/login/start", handlers.WebAuthnLoginStart(...))
  - e.POST("/webauthn/login/finish", handlers.WebAuthnLoginFinish(...))

---

## 12. エラーハンドリング・UX

- 一般エラーは JSON。アプリ側 UI でハンドリング。
- discoverable credentials を使う場合、email 入力無しで "Use a passkey" を出せる。
- 失敗時のガイド（別端末/別ブラウザ/セキュリティキー）をメッセージで案内。

---

## 13. テスト計画

- 単体テスト
  - challenge 生成と TTL 検証
  - attestation/assertion の署名検証（モック/サンプルベクトル）
  - signCount の更新と巻き戻り検知
- 結合テスト
  - start→finish の往復でセッションが発行されること
  - 不正 origin、期限切れ、未知の credentialID の拒否
- 開発者向け動作確認
  - Chrome/Edge/Safari で localhost 運用（必要なら https 自己署名や `chrome://flags/#allow-insecure-localhost`）

---

## 14. ロールアウト

- 段階導入: 管理フラグでパスキー UI を段階公開。
- ドキュメント更新: README に利用手順と制限事項を追記。
- メトリクス: 登録/認証成功率を記録（PII なし）。

---

## 15. リスク・留意点

- ブラウザ/OS 差異（iOS/Safari の挙動差）
- RP ID と origin の誤設定による検証失敗
- ライブラリアップデートへの追随
- セキュリティキーのバックアップ・移行手段に関するユーザーサポート

---

## 16. 参考

- W3C WebAuthn Level 2/3
- FIDO Alliance: Passkeys
- Duo Labs WebAuthn (Go)
- Google, Apple, Microsoft のパスキーガイド
