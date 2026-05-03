# 品質ゲートと CI のセットアップ手順書

このドキュメントは、`nz-magic-link` リポジトリに **lint / test / vuln check / 依存自動更新 / CI** を導入する手順を記述する。

姉妹リポジトリ `github.com/naozine/project_crud_with_auth_tmpl` で同等のセットアップを実施済みで、その内容を本リポジトリに移植する想定。Claude Code に作業させる際の指示書として使う。

---

## 前提

- 現状: `Makefile`、`CLAUDE.md`、`.golangci.yml`、`.github/` がいずれも未設置
- `go.mod`: `go 1.25.0`、依存は `go-webauthn`, `golang.org/x/time`, `modernc.org/sqlite`
- 本リポジトリは **アプリではなくライブラリ**。`main` パッケージは無く、デプロイ系の設定（Docker, fly.io 等）は対象外

---

## ゴール

完了時の状態:
- `make check` (= `fmt + vet + lint + test`) がローカルで緑
- `git push` で GitHub Actions が緑（build / test / golangci-lint / govulncheck / go mod tidy 検証）
- `dependabot` が週次で依存更新 PR を作成
- 派生プロジェクトや利用側で見つかる lint 警告が CI で即時検出される

---

## ステップ

### 1. `.golangci.yml` を作成

ファイル: `.golangci.yml` (リポジトリ直下)

```yaml
version: "2"

run:
  timeout: 5m

linters:
  # standard = errcheck, govet, ineffassign, staticcheck, unused
  default: standard
  enable:
    - gosec
  settings:
    errcheck:
      # 戻り値のエラーを無視しても実害が小さい関数はプロジェクト全体で除外する
      exclude-functions:
        - (io.Closer).Close
        - (*encoding/json.Encoder).Encode
    gosec:
      excludes:
        # G104 (Errors unhandled) は errcheck と機能重複するため除外
        - G104
        # G706 (Log injection) は環境変数や DB 値の log.Printf で誤検知が多いため除外
        - G706

formatters:
  enable:
    - gofmt
    - goimports
```

注意:
- `default: standard` は v2 系の golangci-lint で `errcheck/govet/ineffassign/staticcheck/unused` を有効化する短縮表記
- `exclude-functions` の表記は `(*PkgPath.Type).Method` の形式。具象型を書く必要があり、interface 経由 (`(io.Closer).Close`) では具象型 (`*os.File.Close` 等) を捕捉しないことがある
- 既存コードに DoS 関連の警告 (G120 等) が出る場合は、`internal/limits/` パッケージで定数化 + `MaxBodySize` ミドルウェア導入を検討（姉妹リポを参照）

### 2. `Makefile` を作成

ファイル: `Makefile` (リポジトリ直下)

ライブラリには `generate` (sqlc/templ) が不要、デプロイターゲットも不要。最小構成:

```makefile
# -----------------------------------------------------------------------------
# Code Quality Targets
# -----------------------------------------------------------------------------
.PHONY: fmt vet lint test vuln check

# Format code
fmt:
	@echo ">> Formatting..."
	gofmt -w .

# Run go vet
vet:
	@echo ">> Running go vet..."
	go vet ./...

# Run golangci-lint
# 要: go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest
lint:
	@echo ">> Running golangci-lint..."
	golangci-lint run ./...

# Run tests
test:
	@echo ">> Running tests..."
	go test ./...

# Check known vulnerabilities (要ネットワーク)
vuln:
	@echo ">> Running govulncheck..."
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

# Run all quality checks (lint は要 golangci-lint インストール)
check: fmt vet lint test
```

### 3. GitHub Actions CI を追加

ファイル: `.github/workflows/ci.yml`

```yaml
name: CI

on:
  push:
    branches: [master]
  pull_request:

jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 15

    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-go@v5
        with:
          go-version: '1.25' # マイナーまで指定し、check-latest で常に最新パッチを取得 (stdlib の脆弱性修正を自動反映)
          check-latest: true
          cache: true

      - name: Verify go.mod is tidy
        run: |
          go mod tidy
          git diff --exit-code go.mod go.sum

      - name: Build
        run: go build ./...

      - name: Test
        run: go test ./...

      - name: golangci-lint
        uses: golangci/golangci-lint-action@v8
        with:
          version: v2.11.4

      - name: govulncheck
        run: |
          go install golang.org/x/vuln/cmd/govulncheck@latest
          govulncheck ./...
```

#### 重要な注意事項（姉妹リポの試行錯誤からの学び）

1. **`golangci-lint-action` のバージョン**:
   - `v6 以前` は golangci-lint v1 系のみ対応
   - **v2 系を使うなら `@v8`** が必須
2. **`golangci-lint` のバージョン指定**:
   - `latest` だと v1 系を引いてしまう
   - **`v2.11.4` のように明示的に v2 系を指定**
   - v2.1.x 等の古いマイナーは Go 1.24 でビルドされていて、`go 1.25.x` プロジェクトを解析できない
3. **`setup-go` の Go バージョン**:
   - `go-version-file: go.mod` だと go.mod の値ジャストを使う → 脆弱性のあるパッチに当たる可能性
   - **`go-version: '1.25'` (マイナーのみ) + `check-latest: true`** の組み合わせで、常に 1.25 系の最新パッチを取得
   - これで `crypto/tls`, `crypto/x509`, `net/mail` 等の stdlib 脆弱性を自動回避

### 4. `dependabot` を追加

ファイル: `.github/dependabot.yml`

```yaml
version: 2
updates:
  # Go モジュールの依存
  - package-ecosystem: "gomod"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 5
    commit-message:
      prefix: "deps"

  # GitHub Actions 自体のバージョン (actions/checkout など)
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 3
    commit-message:
      prefix: "ci"
```

### 5. `CLAUDE.md` を作成

ファイル: `CLAUDE.md` (リポジトリ直下)

既存リポジトリ用のものをベースに最低限の内容で:

```markdown
# ルール

- アプリやコマンドの実行は指示がない限り人間がやる（ビルド検証は可）

## 作業完了時

- Go ファイルの変更を伴う作業の最後に `make vet` と `make lint` を実行し、結果を報告する
  - `make lint` で `golangci-lint: command not found` が出たらスキップして報告のみでよい
  - 既存コードに由来する警告（自分が変更していない箇所）は、その旨を明記して区別する
```

なお、グローバル `~/.claude/CLAUDE.md` で「Go プロジェクトのコード調査では LSP (gopls) を優先」が設定済みのため、リポジトリ側で重複指定は不要（書いておいても害なし）。

### 6. 既存 lint 警告の整理

ステップ 1〜5 を完了した後で `make lint` を実行すると、既存コードに由来する警告が大量に出る可能性が高い。姉妹リポでは初期 32 件あった。

#### 対処方針

警告のカテゴリ別に判断:
- **誤検知系** → `.golangci.yml` の `exclude-functions` や `gosec.excludes` に追加
- **`defer Close()` 系** → `defer func() { _ = x.Close() }()` に置換
- **`r.FormValue` / `r.ParseForm` 等の body サイズ無制限警告 (G120)** → `http.MaxBytesReader` を使うミドルウェアを導入し、上限値は `internal/limits/limits.go` に定数化（姉妹リポの実装パターンを参照）
- **未使用関数 (`unused`)** → 削除
- **冗長なエイリアス** → 削除

警告の数が多い場合は **カテゴリごとにコミットを分ける** ことで履歴が読みやすくなる。

### 7. ローカル検証 → push → CI 緑確認

```bash
# ローカル
make check          # fmt → vet → lint → test
make vuln           # 脆弱性チェック (任意、CI でも回る)

# push
git push

# CI 確認
gh run list -L 1
gh run watch <RUN_ID>
```

CI が赤になった場合は、姉妹リポの試行錯誤履歴が参考になる:
- `git log` で `c97a210` 〜 `7342dfe` 付近の CI 修正コミットを参照

---

## 完了条件

- [ ] `.golangci.yml` `Makefile` `.github/workflows/ci.yml` `.github/dependabot.yml` `CLAUDE.md` が存在
- [ ] `make check` が緑（既存警告を整理し終えた状態）
- [ ] GitHub Actions の `CI` ワークフローが緑
- [ ] `dependabot` が GitHub の Insights → Dependency graph で確認できる

---

## 参考: ライブラリ特有の追加検討事項

このリポジトリは **アプリではなくライブラリ** なので、姉妹リポと比べて以下が異なる:

| 項目 | アプリテンプレ (project_crud_with_auth_tmpl) | ライブラリ (このリポジトリ) |
|---|---|---|
| `cmd/` | あり (main パッケージ) | **なし** |
| デプロイ設定 | Dockerfile, fly.toml 等 | 不要 |
| `make generate` | sqlc + templ + tailwind | **不要** (該当ツール無し) |
| バージョニング | アプリ単位 | **SemVer 厳守** (利用側が import するため) |
| API ドキュメント | 派生プロジェクト用の README | **godoc コメント** が主 |

ライブラリ向けに追加で検討してよいもの (このセットアップ手順とは独立):
- 公開 API の **godoc 充実** (`go doc -all ./...` の出力をレビュー)
- `pkg.go.dev` 上の表示確認
- `examples/` ディレクトリの整備
- セマンティックバージョニング・破壊的変更の運用ルール

---

## 想定所要時間

- ステップ 1〜5 の雛形配置: 約 30 分
- ステップ 6 の既存警告整理: コードベースのサイズ次第（30 分〜2 時間）
- ステップ 7 の CI 緑化: 30 分〜1 時間（最初の 1 push で多分赤くなる、調整が要る）

合計: 半日〜1 日程度を見積もる。
