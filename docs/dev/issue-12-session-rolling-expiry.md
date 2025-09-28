# セッション有効期間のローリング更新計画（#12）

作成日: 2025-09-28
担当: @naozine

このドキュメントは Issue #12「ログインして操作をしても、セッションの有効期間が更新されない」への対応計画です。目的は、ユーザーが継続的に操作している限り、セッション有効期限を「最後のアクセス時刻から一定期間」に延長（Sliding/Rolling Expiration）することです。

---

## 1. 現状と課題

- 現状コード
  - セッション管理: `magiclink/internal/session/session.go`
    - `Create`: 新規セッションを発行し、`expiresAt = now + SessionExpiry` を保存。Cookie の Expires も同値。
    - `Validate`: Cookie からセッションを取得し、有効期限切れを判定。期限切れなら削除して false を返す。
    - 課題: `Validate` 内で期限延長も Cookie 更新も行っていないため、継続操作でも期限は固定のまま。
  - ストレージ IF: `magiclink/internal/storage/storage.go`
    - セッション関連: `SaveSession`, `GetSessionByHash`, `DeleteSession`, `CleanupExpiredSessions`
    - 課題: 期限延長を更新するための専用メソッドが存在しない。

- ユーザー要件
  - 「最後にアクセスした時から一定期間」がセッション有効期間になること（ローリング更新）。
  - Cookie の有効期限（Expires/Max-Age）も同様に更新されること。

---

## 2. ゴール/非ゴール

- ゴール
  - 認証済みリクエストごと（もしくは一定間隔で）に、サーバ側のセッション期限とレスポンスの Cookie を延長する。
  - 実装は最小変更で、安全かつ後方互換を保つ。

- 非ゴール（今回のスコープ外）
  - OAuth/OIDC の刷新やセッション多重化管理の大幅な設計変更。
  - 端末・ブラウザ間のセッション共有。

---

## 3. 仕様（提案）

### 3.1 ローリング更新の基本
- `SessionExpiry` をスライディングウィンドウ長とする。
- バリデーション成功時（`Validate`）、以下を行う:
  1) `newExpiresAt = now + SessionExpiry`
  2) DB 上の対象セッションの `expires_at` を `newExpiresAt` に更新
  3) レスポンス Cookie の Expires も `newExpiresAt` で再設定

### 3.2 更新の頻度制御（スロットリング）
- 毎リクエスト更新は DB/IO 負荷と Set-Cookie の過多を招くため、以下のいずれかを採用:
  - 案A（簡易）: 毎回更新（まずは実装容易性を優先）。
  - 案B（推奨）: 有効期限が `SessionExpiry/2` 以内に迫った場合のみ更新。
- 初期実装は案Aで最小変更、その後の最適化で案Bへ切り替え可能にする（フラグ導入も可）。

### 3.3 絶対有効期限（オプション）
- セキュリティ要件として「最大セッション存続時間（Absolute Timeout）」を持たせる案。
- 今回は最小実装のためスコープ外。ただし将来 `AbsoluteSessionLifetime` を `Config` に追加できるようドキュメント化。

### 3.4 Cookie 設定
- 既存の `CookieName`, `Secure`, `HttpOnly`, `SameSite`, `Domain`, `Path` を踏襲。
- ローリング時も同じ属性で `Expires` のみ更新して `Set-Cookie` する。

---

## 4. 設計と最小変更方針

### 4.1 ストレージ層
- IF 追加（最小）:
  - `UpdateSessionExpiry(sessionHash string, newExpiresAt time.Time) error`
- 実装追加:
  - SQLite 実装: `UPDATE sessions SET expires_at=? WHERE session_hash=?`
  - LevelDB 実装: セッションレコードを読み出し、`expires_at` を上書きして保存。

### 4.2 セッション層（session.Manager）
- `Validate` のロジックを以下に変更:
  1) Cookie 取得 → `sessionHash` 算出 → DB 取得
  2) `expiresAt` が `now` より後であることを確認
  3) （案A）常に `newExpiresAt = now + SessionExpiry` として `UpdateSessionExpiry` 実行
  4) 同値の `Expires` を持つ Cookie を `SetCookie` で再送（属性は `Create` と同様）
  5) `userID` を返却

- 例外時の扱い:
  - DB 更新失敗時はログに記録しつつ、今回の応答は成功扱い（セッション自体はまだ有効）。次回以降のリクエストで再試行される前提。

### 4.3 後方互換
- 既存の構成で `SessionExpiry` 値を変えずとも、ローリングにより UX が向上。
- 新規 IF 追加は軽微な変更。`storage` 実装を同時に更新するため破壊的変更には該当しない（コンパイル時点で検出）。

---

## 5. 実装タスク

1) ストレージ IF 追加（`magiclink/internal/storage/storage.go`）
   - `UpdateSessionExpiry(sessionHash string, newExpiresAt time.Time) error`

2) ストレージ実装を更新
   - SQLite: `magiclink/internal/storage/sqlite.go`
   - LevelDB: `magiclink/internal/storage/leveldb.go`

3) セッション層の更新
   - `magiclink/internal/session/session.go` の `Validate` にローリング更新を追加
   - Cookie の再設定（`Expires` 更新）を実装

4) 影響箇所の確認
   - ハンドラ（例: `magiclink/handlers/verify.go`, `handlers/login.go`）は `Validate` の戻り値変更なしでそのまま利用可能

5) ログ/メトリクス（任意）
   - 更新失敗時の警告ログ
   - 更新回数、失敗回数の計測（将来の最適化向け）

---

## 6. テスト計画

- ユニットテスト（session.Manager.Validate）
  - 有効期限内 → ローリング更新で `expires_at` が延長される
  - 期限切れ → セッション削除＆無効判定（従来通り）
  - ストレージ更新失敗 → `Validate` は true を返すが Cookie は非更新 or 直近値、ログ記録
- 結合テスト（サンプル）
  - `SessionExpiry` を短く設定（例: 3s）→ 継続アクセス時に有効期限が伸び続けることを確認
  - アイドルで期限超過 → 以降のアクセスで無効になること
- 負荷・最適化（任意）
  - 更新頻度制御（案B）に切替えた際の DB 書込回数の低減を比較

---

## 7. セキュリティ/運用上の注意

- HTTPS + `Secure` Cookie を前提に運用（ローカル開発を除く）。
- `SameSite` は用途に応じて `Lax` 推奨。クロスサイト要件がある場合は `None` にし、必ず HTTPS を使用する。
- 長期に渡るスライディングはセキュリティリスクになり得るため、将来的に `AbsoluteSessionLifetime` の導入を検討。

---

## 8. ロールアウト

- マイナーリリースとして配布し、リリースノートで「セッションのローリング更新に対応」を明記。
- 設定の破壊的変更はなし（既存 Config をそのまま使用）。
- 監視: 一時的にログレベルを上げ、更新失敗や削除件数の増減を観測。

---

## 9. 変更対象ファイル一覧

- `magiclink/internal/storage/storage.go`
- `magiclink/internal/storage/sqlite.go`
- `magiclink/internal/storage/leveldb.go`
- `magiclink/internal/session/session.go`
- （テスト）`magiclink/handlers/verify_test.go` など、必要に応じて追加

---

## 10. 参考コード断片（擬似）

```text
// storage.go
UpdateSessionExpiry(sessionHash string, newExpiresAt time.Time) error

// session.go (Validate 内)
if time.Now().After(expiresAt) {
    _ = m.DB.DeleteSession(sessionHash)
    return "", false, nil
}

newExpiresAt := time.Now().Add(m.Config.SessionExpiry)
if err := m.DB.UpdateSessionExpiry(sessionHash, newExpiresAt); err != nil {
    // log warn: failed to extend session
} else {
    // Set-Cookie with updated Expires
    cookie := &http.Cookie{ /* 既存属性 */, Expires: newExpiresAt }
    c.SetCookie(cookie)
}
return userID, true, nil
```

---

## 11. 今後の拡張（メモ）

- 絶対有効期限、再認証要求、デバイス別セッション管理、セッション固定化攻撃対策の強化（ログイン直後のセッションIDローテーション等）。
- 更新頻度制御の設定化（例: `RollingUpdateThreshold`）。
