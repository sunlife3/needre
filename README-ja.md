# needre
Linux 上で動作する、自作EDRプログラムです。[Aya](https://aya-rs.dev/) で実装しています。

## 検知できるイベント
- 疑わしいパスのプレフィックス（デフォルト `/tmp`）からの実行を検知します。

## その他機能
- タイムスタンプ付きの検知レコードを `/var/log/needre/needre_detect.log` に記録します。
- すべての監査ログを journald（`info` レベル）へ出力します。
-  systemd サービスとして動作します。

## 必要環境

- Linux 5.8以上（BPF ring buffer マップ型は 5.8 で追加）。
- BTF 有効  （`CONFIG_DEBUG_INFO_BTF=y`）であること。
- Rust ツールチェイン。eBPF クレートのビルドには加えて、`rust-src` を含む nightly
  ツールチェインと eBPF リンカが必要です。
- eBPF プログラムのロードと `/var/log/needre` への書き込みのため root 権限。

## ビルド

```sh
# リリースバイナリをビルド（eBPF オブジェクトとユーザー空間ローダをコンパイル）
cargo build --release
```

## サービスとしてのインストールと起動
```sh
# バイナリをインストール
sudo install -m 755 target/release/needre /usr/local/bin/needre

# systemd サービスをインストールして有効化
sudo cp needre.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now needre

# 起動を確認
systemctl status needre
```
ユニットは `Type=simple` で `Restart=on-failure`・`RestartSec=5` を指定しているため、
クラッシュ時には自動的に再起動されます。

## ログ

出力は 2 系統に分かれています。

- **監査ログ** — すべての `execve` を `info` レベルで記録し、journald が取り込みます。
  ```sh
  journalctl -u needre -f
  ```
- **検知ログ** — 疑わしい実行のみを、ローカル時刻のタイムスタンプ付きで
  `/var/log/needre/needre_detect.log` に追記します。
  ```
  2026-06-06 12:34:56 [DETECT] execution from /tmp | pid=... tgid=... uid=... comm="test_exec" path="/tmp/test_exec"
  ```
  （デフォルト `/var/log/needre/needre_detect.log`）。

## 使い方
```sh
# 1. リリースバイナリをビルド
cargo build --release

# 2. バイナリをインストール
sudo install -m 755 target/release/needre /usr/local/bin/needre

# 3. サービスをインストールして有効化
sudo cp needre.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now needre

# 4. サービスの起動を確認
systemctl status needre

# 5. 検知をトリガー（別のターミナルで実行）
cp /bin/ls /tmp/test_exec && /tmp/test_exec

# 6. 検知ログを確認
cat /var/log/needre/needre_detect.log
# 期待される出力:
# 2026-06-06 12:34:56 [DETECT] execution from /tmp | pid=... comm="test_exec" path="/tmp/test_exec"

# 7. 正常終了のテスト
sudo systemctl stop needre
# クラッシュせずに停止し、journald に "needre shutting down" が出力されるはず
journalctl -u needre -n 20
```

## ライセンス
With the exception of eBPF code, needre is distributed under the terms
of either the [MIT license] or the [Apache License] (version 2.0), at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.

### eBPF

All eBPF code is distributed under either the terms of the
[GNU General Public License, Version 2] or the [MIT license], at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this project by you, as defined in the GPL-2 license, shall be
dual licensed as above, without any additional terms or conditions.

[Apache license]: LICENSE-APACHE
[MIT license]: LICENSE-MIT
[GNU General Public License, Version 2]: LICENSE-GPL2

