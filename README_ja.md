[English](README.md) | [简体中文](README_cn.md) | [Español](README_es.md) | [हिन्दी](README_hi.md) | [العربية](README_ar.md) | [Français](README_fr.md) | [Português](README_pt.md) | [Русский](README_ru.md) | [বাংলা](README_bn.md) | [اردو](README_ur.md) | [日本語](README_ja.md) | [Deutsch](README_de.md) | [Bahasa Indonesia](README_id.md) | [한국어](README_ko.md)


<div align="center">
 <img alt="SamWaf" width="100" src="./docs/images/logo.png"> 

軽量なオープンソースのWebアプリケーションファイアウォール

[![Release](https://img.shields.io/github/release/samwafgo/SamWaf.svg)](https://github.com/samwafgo/SamWaf/releases)
[![Last commit](https://img.shields.io/github/last-commit/samwafgo/SamWaf?style=flat-square&color=blue&logo=github)](https://github.com/samwafgo/SamWaf/releases)
[![Docker Pulls](https://img.shields.io/docker/pulls/samwaf/samwaf?style=flat-square&color=blue&label=Docker+Image+Pulls)](https://hub.docker.com/r/samwaf/samwaf)
[![Release Downloads](https://img.shields.io/github/downloads/samwafgo/samwaf/total?style=flat-square&color=blue&label=Release+Downloads)](https://github.com/samwafgo/SamWaf/releases)
[![Gitee](https://img.shields.io/badge/Gitee-blue?style=flat-square&logo=Gitee)](https://gitee.com/samwaf/SamWaf)
[![GitHub stars](https://img.shields.io/github/stars/samwafgo/SamWaf?style=flat-square&logo=Github)](https://github.com/samwafgo/SamWaf)
[![Gitee star](https://gitee.com/samwaf/SamWaf/badge/star.svg?theme=gray)](https://gitee.com/samwaf/SamWaf)
[![Atomgit star](https://atomgit.com/SamSafe/SamWaf/star/badge.svg)](https://atomgit.com/SamSafe/SamWaf)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue?style=flat-square)](LICENSE)
</div>

  
## 開発の動機：
- **軽量**：当初は nginx、apache、iis のプラグインをベースにしたセキュリティ製品で防御していましたが、プラグイン形式は結合度が高いという課題がありました。
- **プライベート化**：その後、クラウド型の防御サービスが広く採用されるようになりましたが、プライベートデプロイを導入できるのは中堅・大企業に限られ、小規模企業やスタジオにとってはコストが高くつきます。
- **プライバシー暗号化**：Web を防御する際は、データをクラウドへ送信せずローカルで処理することが望ましいと考えています。ローカルの情報と管理側のネットワーク通信を暗号化するツールを作ることを目指しました。
- **DIY**：長年にわたる Web サイトの運用・開発の中で、追加したくても実現できない機能がありました。
- **状況把握**：同様の WAF を使ったことがないと、サイト管理者はログや nginx、apache、IIS などからだけでは、誰がサイトにアクセスし、どのようなリクエストが行われているのかを把握しにくいものです。

要するに、Web サイトや API を保護する効果的なツールを作り、異常事態に対処して Web サイトとアプリケーションの正常な稼働を確保することが目標です。

# ソフトウェア紹介
SamWaf は、小規模企業・スタジオ・個人サイト向けの軽量なオープンソース Web アプリケーションファイアウォールです。完全なプライベートデプロイに対応し、データは暗号化してローカルに保存されます。起動も簡単で、Linux、Windows 64 ビット、ARM64 をサポートし、Docker イメージも提供されています。デフォルトでは外部依存ゼロの組み込み暗号化 SQLite データベースを使用し、必要に応じて MySQL へ切り替えることも可能です。

## アーキテクチャ

![SamWaf アーキテクチャ](./docs/images_en/tecDesign.svg)

## インターフェース
![SamWaf Web アプリケーションファイアウォール概要](/docs/images_en/overview.png)

<table>
    <tr>
        <td align="center">ホスト追加</td>
        <td align="center">攻撃ログ</td>
    </tr>
    <tr>
        <td><img src="./docs/images_en/add_host.png" alt="ホスト追加"/></td>
        <td><img src="./docs/images_en/attacklog.png" alt="攻撃ログ"/></td>
    </tr>
    <tr>
        <td align="center">CC</td>
        <td align="center">IPブロックリスト</td>
    </tr>
    <tr>
        <td><img src="./docs/images_en/cc.png" alt="CC"/></td>
        <td><img src="./docs/images_en/ipblock.png" alt="IPブロックリスト"/></td>
    </tr>
    <tr>
        <td align="center">IP許可リスト</td>
        <td align="center">LDP</td>
    </tr>
    <tr>
        <td><img src="./docs/images_en/ipallow.png" alt="IP許可リスト"/></td>
        <td><img src="./docs/images_en/ldp.png" alt="LDP"/></td>
    </tr>
    <tr>
        <td align="center">ルールスクリプト追加ログ</td>
        <td align="center">ログ選択</td>
    </tr>
    <tr>
        <td><img src="./docs/images_en/log_add_rule_script.png" alt="ルールスクリプト追加ログ"/></td>
        <td><img src="./docs/images_en/log_select.png" alt="ログ選択"/></td>
    </tr>
    <tr>
        <td align="center">ログ詳細</td>
        <td align="center">手動ルール</td>
    </tr>
    <tr>
        <td><img src="./docs/images_en/logdetail.png" alt="ログ詳細"/></td>
        <td><img src="./docs/images_en/manual_rule.png" alt="手動ルール"/></td>
    </tr>
    <tr>
        <td align="center">URLブロックリスト</td>
        <td align="center">URL許可リスト</td>
    </tr>
    <tr>
        <td><img src="./docs/images_en/urlblock.png" alt="URLブロックリスト"/></td>
        <td><img src="./docs/images_en/urlallow.png" alt="URL許可リスト"/></td>
    </tr>
</table>

## 主な機能

### 基本
- 完全オープンソースのコード（Apache 2.0）
- 完全なプライベートデプロイに対応。データは暗号化のうえローカルのみに保存されます
- 単一ファイルでワンクリック起動。サードパーティサービスへの依存がない軽量設計（MySQL/Redis はオプション）
- 完全に独立したエンジン。防御は IIS や Nginx に依存しません
- IPv6 対応

### トラフィックアクセス
- HTTP/1.1、HTTP/2、HTTP/3（QUIC）対応
- WebSocket 転送
- ロードバランシング対応のリバースプロキシ（重み付きラウンドロビン、IP ハッシュ、最小コネクション）。ヘルスチェックにより異常なバックエンドを自動的に除外します
- パスルール：パス単位のリバースプロキシ、静的ファイル配信、301/302 リダイレクトに対応し、バックエンドプロトコルとレスポンスタイムアウトを設定可能
- 静的サイト配信
- TCP/UDP レイヤー4 トンネル転送（IP アクセス制御・時間帯制御付き）
- Web ページキャッシュ
- サイトアクセス向けの HTTP Basic 認証
- カスタマイズ可能なブロックページ

### 攻撃防御
- SQLインジェクション検知
- XSS（クロスサイトスクリプティング）検知
- RCE（リモートコマンド実行）検知
- スキャナーツール検知
- パストラバーサル検知
- ファイルアップロード検査（危険な拡張子、Webシェルシグネチャ、偽装された Content-Type）
- CC / レート制限による防御
- 偽クローラー／ボット検知（検索エンジンボットの逆引き DNS 検証）
- 直リンク防止（ホットリンク保護）
- CSRF 対策（サイト単位の Origin/Referer 検証）
- センシティブワードフィルタリング
- OWASP CRS ルールセット対応（Coraza エンジン。ルールの有効化／無効化／上書きが可能）
- カスタマイズ可能な防御ルール（スクリプト編集と GUI 編集の両方に対応）
- 人間認証：クリック式 CAPTCHA および Cap.js による Proof-of-Work
- ログのみモード：ブロックせずに攻撃を記録し、ルールの観察やチューニングに役立ちます

### アクセス制御
- IP 許可リスト／ブロックリスト
- URL 許可リスト／ブロックリスト
- 地域ブロック（オフラインの ip2region/GeoIP2 データベースを内蔵、IPv4/IPv6 対応）
- OS ファイアウォールと連動した IP 遮断
- IP の失敗回数がしきい値に達した場合の自動遮断
- グローバルなワンクリック設定とサイト単位の防御戦略

### データセキュリティ
- ログの暗号化保存
- 通信ログの暗号化
- データマスキング（DLP）。指定したデータをプライバシー保護して出力します
- Web ページ改ざん防止（ベースライン学習＋自動復旧）
- Cookie セキュリティ強化（HttpOnly/Secure/SameSite）

### SSL証明書
- SSL証明書の自動申請・自動更新（ACME、EAB 対応のマルチ CA）
- SNI マルチ証明書およびマルチポート HTTPS
- SSL証明書有効期限の一括チェック
- 証明書の自動読み込み

### 運用・管理
- アカウントの RBAC、OTP 二要素認証、ログイン／操作ログ
- 統計レポートとシステム／ホスト監視
- ログの自動シャーディングとアーカイブを備えたデータ保持ポリシー
- デフォルトは SQLite（暗号化）、オプションで MySQL に対応。SQLite→MySQL 移行ツールを内蔵
- オンラインワンクリックアップグレード、ゼロダウンタイムのローリング再起動、バージョンロールバック
- バッチタスク、スケジュールタスク、データバックアップ
- オープン API

### 通知
- メール、DingTalk、Feishu、WeCom（WeChat Work）、ServerChan、Webhook、Kafka、RabbitMQ、およびログファイルへの通知チャネル

# 使用方法
**本番環境へデプロイする前に、テスト環境で十分なテストを行うことを強く推奨します。問題が発生した場合は、速やかにフィードバックをお寄せください。**
## 最新バージョンのダウンロード
Gitee:  [https://gitee.com/samwaf/SamWaf/releases](https://gitee.com/samwaf/SamWaf/releases)

GitHub: [https://github.com/samwafgo/SamWaf/releases](https://github.com/samwafgo/SamWaf/releases)

AtomGit: [https://atomgit.com/SamSafe/SamWaf/releases](https://atomgit.com/SamSafe/SamWaf/releases)

## クイックスタート

### Windows
- 直接起動
```
SamWaf64.exe
```
- サービスとして実行（管理者権限が必要）
```
//Install & Start
SamWaf64.exe install && SamWaf64.exe start

//Stop &  Uninstall 
SamWaf64.exe stop && SamWaf64.exe uninstall
``` 

### Linux
- インストール
```
curl -sSO https://update.samwaf.com/latest/install_samwaf.sh && bash install_samwaf.sh install 
``` 

- アンインストール
```
curl -sSO https://update.samwaf.com/latest/install_samwaf.sh && bash install_samwaf.sh uninstall 
```

### Docker
```
docker run -d --name=samwaf-instance \
           --restart always \
           -p 26666:26666 \
           -p 80:80 \
           -p 443:443 \
           -v /path/to/your/conf:/app/conf \
           -v /path/to/your/data:/app/data \
           -v /path/to/your/logs:/app/logs \
           -v /path/to/your/ssl:/app/ssl \
           samwaf/samwaf


```
Docker の詳細はこちら https://hub.docker.com/r/samwaf/samwaf

タグ：
- **latest**：最新の安定版リリース（本番環境での利用を推奨）。
- **beta**：最新のテスト版（新機能や特定のバグ修正を試すことができます）。

### コマンドラインツール

| Command | 説明 |
|---------|-------------|
| `install` / `uninstall` | システムサービスのインストール／アンインストール |
| `start` / `stop` / `restart` | サービスの起動／停止／再起動 |
| `rolling-restart` | ゼロダウンタイムのローリング再起動（トラフィックを中断せずにワーカーを入れ替え） |
| `resetpwd` | 管理者パスワードのリセット |
| `resetotp` | セキュリティコード（OTP）のリセット |
| `repairdb` | 破損したデータベースの修復 |
| `execsql` | 選択したデータベースに対して SQL 文を実行 |
| `migratedb` | SQLite → MySQL のオフラインデータベース移行（`--dry-run` で見積もりのみ、`--force` で上書き） |
| `rollback` | 以前のバックアップバージョンへのロールバック |

例：`SamWaf64.exe resetpwd`（Linux の場合：`./SamWafLinux64 resetpwd`）

## アクセス開始

http://127.0.0.1:26666

デフォルトアカウント: admin  初期パスワード: 新規インストールではランダムなパスワードが自動生成され `data/initial_password.txt` に保存されます（既存インストールは以前のパスワードを維持します。初回ログイン時に必ず変更してください）


## アップグレードガイド

**注意：アップグレード処理中はサービスが停止するため、アクセスの少ない時間帯にアップグレードを実施してください。**

### 自動アップグレード
新しいバージョンが利用可能な場合、確認のためのアップグレードプロンプトが表示され、そこからアップグレードを開始できます。アップグレード完了後、ページは自動的に更新されます。

### 手動アップグレード
- 直接起動の場合：
    1. アプリケーションを終了します。
    2. 最新のプログラムをダウンロードして既存のファイルを置き換え、再度手動で起動します。

- サービスモードの場合：
```
1. First, pause the service.

  Windows: SamWaf64.exe stop
  Linux: ./SamWafLinux64 stop
  
2. Replace with the latest application files.

3. Start the service:
Windows: SamWaf64.exe start
Linux: ./SamWafLinux64 start
```

**注意**：Windows サービスのアップグレード時に、360 や Huorong のセキュリティルールが作動し、新しいファイルへの置き換えが正常に行われないことがあります。その場合は、手動でファイルを置き換えてください。この分野に詳しい方は、適切な対処方法の判断にご協力ください。

## オンラインドキュメント

[オンラインドキュメント](https://doc.samwaf.com/)

# コード情報
## コードリポジトリ
- Gitee
[https://gitee.com/samwaf/SamWaf](https://gitee.com/samwaf/SamWaf)
- GitHub
[https://github.com/samwafgo/SamWaf](https://github.com/samwafgo/SamWaf)
- Atomgit
[https://atomgit.com/SamSafe/SamWaf](https://atomgit.com/SamSafe/SamWaf)

## 紹介とコンパイル
コンパイル方法
[コンパイル手順](./docs/compile.md)

コンパイルオンラインマニュアル：
[https://doc.samwaf.com/en/dev/](https://doc.samwaf.com/en/dev/)

## テスト済み・サポート対象プラットフォーム
[テスト済み・サポート対象プラットフォーム](./docs/Tested_supported_systems.md)

## その他の情報 

- [IPデータベースの更新](./docs/ipmodify.md)

## テスト結果
[テスト結果](./test/attackTest.md)

# セキュリティポリシー
[セキュリティポリシー](./SECURITY.md)

# フィードバック
SamWaf は継続的に改善を続けています。フィードバックやご提案を歓迎します。

- [Gitee Issues](https://gitee.com/samwaf/SamWaf/issues)
- [GitHub Issues](https://github.com/samwafgo/SamWaf/issues)
- [Atomgit Issues](https://atomgit.com/SamSafe/SamWaf/issues)
- メールでのフィードバック：samwafgo@gmail.com

# WeChat 公式アカウント

<img alt="SamWaf" width="400px"  src="./docs/images/mp_samwaf.png"> 

## Star 履歴

[![Star History チャート](https://api.star-history.com/svg?repos=samwafgo/samwaf&type=Date)](https://star-history.com/#samwafgo/samwaf&Date)


#  ライセンス
SamWaf は Apache License 2.0 の下でライセンスされています。詳細は [LICENSE](./LICENSE) をご覧ください。

サードパーティソフトウェアの使用に関する通知については、[ThirdLicense](./ThirdLicense) を参照してください

# コントリビューション
 以下のコントリビューターの皆様に感謝します！

<a href="https://github.com/samwafgo/SamWaf/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=samwafgo/SamWaf" />
</a>
