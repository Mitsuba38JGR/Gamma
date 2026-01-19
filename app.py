import streamlit as st
import openai
import gspread
from oauth2client.service_account import ServiceAccountCredentials
from datetime import datetime
import hashlib
import re

# --- 設定 ---
# スプレッドシート名
SHEET_NAME = "ai_memo_auth_db"
# シート内のワークシート名定義
WS_USERS = "users"  # ユーザー管理用
WS_LOGS = "logs"    # 履歴保存用

# --- 関数定義: データベース（スプレッドシート）接続 ---

def connect_to_sheet():
    """Googleスプレッドシートに接続し、必要なワークシートを取得する"""
    try:
        creds_dict = st.secrets["gcp_service_account"]
        scope = ["https://spreadsheets.google.com/feeds", "https://www.googleapis.com/auth/drive"]
        creds = ServiceAccountCredentials.from_json_keyfile_dict(creds_dict, scope)
        client = gspread.authorize(creds)
        
        # スプレッドシートを開く
        try:
            sh = client.open(SHEET_NAME)
        except gspread.SpreadsheetNotFound:
            st.error(f"スプレッドシート '{SHEET_NAME}' が見つかりません。作成してください。")
            return None, None

        # ワークシートの取得（なければ作成）
        try:
            ws_users = sh.worksheet(WS_USERS)
        except:
            ws_users = sh.add_worksheet(title=WS_USERS, rows="100", cols="2")
            ws_users.append_row(["user_id", "password_hash"]) # ヘッダー

        try:
            ws_logs = sh.worksheet(WS_LOGS)
        except:
            ws_logs = sh.add_worksheet(title=WS_LOGS, rows="1000", cols="4")
            ws_logs.append_row(["timestamp", "user_id", "input", "ai_response"]) # ヘッダー

        return ws_users, ws_logs

    except Exception as e:
        st.error(f"DB接続エラー: {e}")
        return None, None

# --- 関数定義: 認証・ユーティリティ ---

def make_hash(password):
    """パスワードをハッシュ化する"""
    return hashlib.sha256(str.encode(password)).hexdigest()

def check_login(ws_users, user_id, password):
    """ログインチェック"""
    # 全ユーザー取得
    users = ws_users.get_all_records()
    hashed_pw = make_hash(password)
    
    for user in users:
        # スプレッドシートのカラム名に合わせて修正
        if str(user.get("user_id")) == user_id and user.get("password_hash") == hashed_pw:
            return True
    return False

def register_user(ws_users, user_id, password):
    """新規ユーザー登録"""
    # 既存チェック
    users = ws_users.col_values(1) # 1列目(ID)を全て取得
    if user_id in users:
        return False, "このIDは既に使用されています。"
    
    # 登録処理
    hashed_pw = make_hash(password)
    ws_users.append_row([user_id, hashed_pw])
    return True, "登録しました！ログインしてください。"

def validate_input(user_id, password):
    """IDとパスワードの形式チェック"""
    # ID: 英数字 + ひらがな
    id_pattern = re.compile(r'^[a-zA-Z0-9\u3040-\u309F]+$')
    # PASS: 英数字のみ
    pw_pattern = re.compile(r'^[a-zA-Z0-9]+$')

    if not id_pattern.match(user_id):
        return False, "IDは「英数字」または「ひらがな」のみ使用できます。"
    if not pw_pattern.match(password):
        return False, "パスワードは「英数字」のみ使用できます。"
    return True, ""

def get_ai_response(user_input):
    """OpenAI API呼び出し"""
    try:
        client = openai.OpenAI(api_key=st.secrets["openai"]["api_key"])
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "あなたは優秀なアシスタントです。"},
                {"role": "user", "content": user_input}
            ]
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"AI Error: {e}"

# --- アプリケーション本体 ---

st.set_page_config(page_title="Cloud AI Memo", page_icon="☁️")
st.title("☁️ どこでも AIメモ (要ログイン)")

# シート接続
ws_users, ws_logs = connect_to_sheet()

if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.user_id = ""

# --- ログイン前: 認証画面 ---
if not st.session_state.logged_in:
    tab1, tab2 = st.tabs(["ログイン", "新規登録"])

    # ログインタブ
    with tab1:
        st.subheader("ログイン")
        l_user = st.text_input("ユーザーID", key="l_user")
        l_pass = st.text_input("パスワード", type="password", key="l_pass")
        
        if st.button("ログインする"):
            if ws_users and check_login(ws_users, l_user, l_pass):
                st.session_state.logged_in = True
                st.session_state.user_id = l_user
                st.rerun() # 画面リロード
            else:
                st.error("IDまたはパスワードが間違っています。")

    # 新規登録タブ
    with tab2:
        st.subheader("新規登録")
        st.caption("ID: 英数ひらがな / Pass: 英数")
        r_user = st.text_input("希望ユーザーID", key="r_user")
        r_pass = st.text_input("パスワード", type="password", key="r_pass")
        
        if st.button("登録する"):
            valid, msg = validate_input(r_user, r_pass)
            if valid:
                success, reg_msg = register_user(ws_users, r_user, r_pass)
                if success:
                    st.success(reg_msg)
                else:
                    st.error(reg_msg)
            else:
                st.warning(msg)

# --- ログイン後: メイン画面 ---
else:
    st.success(f"ようこそ、{st.session_state.user_id} さん")
    
    # ログアウトボタン
    if st.button("ログアウト"):
        st.session_state.logged_in = False
        st.session_state.user_id = ""
        st.rerun()
    
    st.divider()

    # メモ入力フォーム
    with st.form("memo_form", clear_on_submit=True):
        user_input = st.text_area("内容を入力", height=100)
        submitted = st.form_submit_button("AIに送信 & 記録")

        if submitted and user_input:
            with st.spinner("処理中..."):
                # AI応答
                ai_reply = get_ai_response(user_input)
                
                # スプレッドシートに保存
                now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                # カラム: timestamp, user_id, input, ai_response
                ws_logs.append_row([now, st.session_state.user_id, user_input, ai_reply])
                
                st.success("記録しました！")

    # 自分の履歴のみ表示
    st.subheader("📖 あなたの記録履歴")
    if ws_logs:
        all_logs = ws_logs.get_all_records()
        # 自分のIDのデータだけ抽出 & 新しい順に
        my_logs = [log for log in all_logs if str(log.get("user_id")) == st.session_state.user_id]
        
        if my_logs:
            for log in reversed(my_logs):
                timestamp = log.get("timestamp")
                u_text = log.get("input")
                a_text = log.get("ai_response")
                
                with st.expander(f"{timestamp} - {str(u_text)[:15]}..."):
                    st.write(f"**あなた:** {u_text}")
                    st.info(f"**AI:** {a_text}")
        else:
            st.write("まだ履歴はありません。")
