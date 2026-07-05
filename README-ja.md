# neEDRe
Linux 上で動作する、自作EDRプログラムです。[Aya](https://aya-rs.dev/) で実装しています。

## 検知できるイベント
- 疑わしいパスのプレフィックス（デフォルト `/tmp`）からの実行を検知します。

## その他機能
- 検知内容を `/var/log/needre/needre_detect.log` に記録します。
- すべての監査ログを journald（`info` レベル）へ出力します。
-  systemd サービスとして動作します。

## 動作環境

- Linux 5.8以上
- eBPF プログラムのロードと `/var/log/needre` への書き込みに root 権限を必要としています。

## ログ
- needreのログを `info` レベルでjournald に記録します。
  ```sh
  journalctl -u needre -f
  ```
- 検知ログ：セキュリティイベントを記録します。（デフォルトパス `/var/log/needre/needre_detect.log`）。
  ```
  2026-06-06 12:34:56 [DETECT] execution from /tmp | pid=... tgid=... uid=... comm="test_exec" path="/tmp/test_exec"
  ```

## 使い方
```sh
# 1. ビルド
cargo build --release

# 2. バイナリをインストール
sudo install -m 755 target/release/needre /usr/local/bin/needre

# 3. サービスをインストールして有効化
sudo cp needre.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now needre

# 3. サービスの起動を確認
systemctl status needre

# 4. 検知ログを確認
cat /var/log/needre/needre_detect.log

# 5. 終了
sudo systemctl stop needre
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

