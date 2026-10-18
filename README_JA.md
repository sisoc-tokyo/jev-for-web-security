# Jev for Web Security — 日本語クイックスタート

単発のHTTP要求だけでなく、アクセス先や方法を変えながら試行を続ける系列を調べる、読み取り専用のプロトタイプです。TypeSafeの公式製品ではありません。

## まず動かす

Python 3.10以上が必要です。追加ライブラリのインストールは不要です。

Windowsでは、ZIPを展開し、run.pyと同じ場所にあるSTART_WINDOWS.batをダブルクリックします。macOS/Linuxでは、ターミナルでそのフォルダを開き、次を実行します。

```sh
python3 run.py
```

ブラウザーで http://127.0.0.1:8765/ を開きます。Scenarioを選び、Analyze sequenceを押してください。Window sizeを5・20・50などに変え、もう一度解析すると、与える文脈の違いを確認できます。番号をクリックすると、その判定に使った観測値が表示されます。

初期状態の **OFFLINE RULE BASELINE** はルール判定です。Jevの推論結果ではありません。サンプルは4種類×80件の説明用合成ログであり、実際にAIエージェントを動かして取得したものではありません。

## Jevを使う

WindowsのPowerShellでは次を実行します。macOS/Linuxは py -3 を python3 に置き換えます。

```powershell
py -3 run.py serve --engine jev --ask-key
```

ターミナルに表示される入力欄へ、ご自身のTypeSafe APIキーを貼り付けます。キーは保存しません。ブラウザーで外部API送信の同意欄を確認してから実行します。API呼び出しには料金がかかる場合があります。実ログの外部送信には承認が必要です。キーをGitHubやチャットに貼り付けないでください。

この配布版では、Jevクライアントの実装と模擬応答によるスキーマ試験を行いましたが、実APIへの接続確認は未実施です。エラー時にルールの結果へ置き換えることはありません。

## Windowの初期設定

直近最大20件、5件ごとの再判定、短期は過去5分、履歴集計は過去30分です。最初の1件でも部分窓として判定します。無通信中にタイマーで判定する機能はなく、新たなログを受け取った時に処理します。最適値は今後の比較実験で検証します。

## 入力と範囲

標準化したJSONLと、文書化したModSecurity v3 JSONの一部に対応します。ModSecurity本体の組み込み、リアルタイム収集、遮断、ASNの自動照合は含みません。信頼できるactor_idがない場合は送信元IPでまとめますが、同じIPが同じ利用者を意味するわけではありません。

詳しくは [英語の説明書](docs/TOOL_GUIDE_EN.pdf)、[入力形式](docs/INPUT_FORMAT.md)、[Window仕様](docs/WINDOWS.md)、[安全上の注意](docs/SECURITY.md) を参照してください。

## テストと公開用ZIP

```powershell
py -3 -m unittest discover -s tests -v
py -3 prepare_git_upload.py
```

後者は公開対象のファイルだけをZIPへまとめます。GitHubへのアップロードやリポジトリ作成は行いません。MITライセンスはこのリポジトリのコードに適用され、Jevのモデル本体やAPIサービスを含みません。