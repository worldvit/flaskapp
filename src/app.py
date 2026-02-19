import os
import re
from datetime import datetime, timedelta
import calendar
from dotenv import load_dotenv, find_dotenv
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import pymysql.cursors

# 도커 환경에 맞게 .env 파일을 상대 경로로 안전하게 로드합니다.
dotenv_path = find_dotenv('.env')
if os.path.exists(dotenv_path):
    load_dotenv(dotenv_path)

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', os.urandom(24).hex())

DB_CONFIG = {
    'host': os.getenv('DB_HOST', 'db'),
    'user': os.getenv('DB_USER', 'flask_user'),
    'password': os.getenv('DB_PASSWORD', 'P@ssword'),
    'db': os.getenv('DB_NAME', 'flask_auth_db'),
    'charset': 'utf8mb4',
    'cursorclass': pymysql.cursors.DictCursor
}

def get_db_connection():
    """데이터베이스 연결을 설정하고 반환합니다."""
    try:
        conn = pymysql.connect(**DB_CONFIG)
        return conn
    except pymysql.Error as e:
        flash('데이터베이스 연결 오류가 발생했습니다. 잠시 후 다시 시도해주세요.', 'error')
        print(f"DB Connection Error: {e}") 
        raise

# --- Helper Functions ---
def is_password_strong(password):
    if len(password) < 8:
        return False
    rules = [
        any(c.isupper() for c in password),
        any(c.islower() for c in password),
        any(c.isdigit() for c in password),
        any(c in "!@#$%^&*()_+-=:,.<>?/[]{}" for c in password)
    ]
    return sum(rules) == 4

def is_valid_phone_number(phone_number):
    pattern = re.compile(r'^(010\d{8}|01[1,6-9]\d{7,8})$')
    return pattern.match(phone_number)

def is_admin():
    return 'username' in session and session['username'] in ['kevin', 'kwangjin']

# --- 사용자 인증 및 암호 재설정 관련 라우트 ---
@app.route('/')
def index():
    if 'loggedin' in session:
        return render_template('main_logged_in.html')
    return render_template('default.html')

@app.route('/register', methods=['POST'])
def register():
    username = request.form['username'].strip()
    phone_number = request.form['phone_number'].strip()
    password = request.form['password'].strip()

    if not all([username, phone_number, password]):
        flash('사용자 이름, 휴대폰 번호, 비밀번호를 모두 입력해주세요.', 'error')
        return redirect(url_for('index'))

    if not is_valid_phone_number(phone_number):
        flash('올바른 핸드폰 번호 형식이 아닙니다. (예: 01012345678)', 'error')
        return redirect(url_for('index'))

    if not is_password_strong(password):
        flash('비밀번호는 8자 이상이며, 영문 대/소문자, 숫자, 특수문자를 모두 포함해야 합니다.', 'error')
        return redirect(url_for('index'))

    hashed_password = generate_password_hash(password)
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
            if cursor.fetchone():
                flash('이미 존재하는 사용자 이름입니다.', 'error')
                return redirect(url_for('index'))

            cursor.execute("SELECT id FROM users WHERE phone_number = %s", (phone_number,))
            if cursor.fetchone():
                flash('이미 등록된 휴대폰 번호입니다.', 'error')
                return redirect(url_for('index'))

            sql = "INSERT INTO users (username, phone_number, password) VALUES (%s, %s, %s)"
            cursor.execute(sql, (username, phone_number, hashed_password))
            conn.commit()
            flash('회원가입에 성공했습니다! 이제 로그인할 수 있습니다.', 'success')
    except Exception as e:
        flash('회원가입에 실패했습니다. 잠시 후 다시 시도해주세요.', 'error')
    finally:
        if conn:
            conn.close()
    return redirect(url_for('index'))

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username'].strip()
    password = request.form['password'].strip()

    if not username or not password:
        flash('사용자 이름과 비밀번호를 모두 입력해주세요.', 'error')
        return redirect(url_for('index'))

    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            sql = "SELECT id, username, password FROM users WHERE username = %s"
            cursor.execute(sql, (username,))
            user = cursor.fetchone()

            if user and check_password_hash(user['password'], password):
                session['loggedin'] = True
                session['id'] = user['id']
                session['username'] = user['username']
                flash(f'환영합니다. {user["username"]}님!', 'success')
                return redirect(url_for('index'))
            else:
                flash('잘못된 사용자 이름 또는 비밀번호입니다.', 'error')
    except Exception as e:
        flash('로그인에 실패했습니다. 서버 오류입니다.', 'error')
    finally:
        if conn:
            conn.close()
    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.clear()
    flash('성공적으로 로그아웃되었습니다.', 'success')
    return redirect(url_for('index'))

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        username = request.form['username'].strip()
        phone_number = request.form['phone_number'].strip()

        if not username or not is_valid_phone_number(phone_number):
            flash('아이디와 올바른 핸드폰 번호 형식을 모두 입력해주세요.', 'error')
            return redirect(url_for('forgot_password'))

        conn = None
        try:
            conn = get_db_connection()
            with conn.cursor() as cursor:
                sql = "SELECT id FROM users WHERE username = %s AND phone_number = %s"
                cursor.execute(sql, (username, phone_number))
                user = cursor.fetchone()

                if user:
                    session['phone_to_reset'] = phone_number
                    flash('계정이 확인되었습니다. 새 비밀번호를 설정해주세요.', 'success')
                    return redirect(url_for('reset_password'))
                else:
                    flash('입력하신 정보와 일치하는 계정을 찾을 수 없습니다.', 'error')
        except Exception as e:
            flash('오류가 발생했습니다. 잠시 후 다시 시도해주세요.', 'error')
        finally:
            if conn:
                conn.close()
    return render_template('forgot_password.html')

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if 'phone_to_reset' not in session:
        flash('먼저 계정 확인 절차를 진행해주세요.', 'error')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        new_password = request.form['new_password'].strip()
        confirm_password = request.form['confirm_password'].strip()

        if new_password != confirm_password:
            flash('새 비밀번호가 일치하지 않습니다.', 'error')
            return render_template('reset_password.html')

        if not is_password_strong(new_password):
            flash('새 비밀번호는 8자 이상이며, 영문 대/소문자, 숫자, 특수문자를 모두 포함해야 합니다.', 'error')
            return render_template('reset_password.html')

        hashed_password = generate_password_hash(new_password)
        phone_number = session['phone_to_reset']
        conn = None
        try:
            conn = get_db_connection()
            with conn.cursor() as cursor:
                sql = "UPDATE users SET password = %s WHERE phone_number = %s"
                cursor.execute(sql, (hashed_password, phone_number))
                conn.commit()
                flash('비밀번호가 성공적으로 변경되었습니다. 새로운 비밀번호로 로그인해주세요.', 'success')
                session.pop('phone_to_reset', None)
                return redirect(url_for('index'))
        except Exception as e:
            flash('비밀번호 변경 중 오류가 발생했습니다.', 'error')
        finally:
            if conn:
                conn.close()
    return render_template('reset_password.html')

# --- 게시판 관련 라우트 ---
@app.route('/board')
def board_list():
    if 'loggedin' not in session:
        flash('게시판을 보려면 로그인해야 합니다.', 'error')
        return redirect(url_for('index'))

    search_query = request.args.get('query', '').strip()
    conn = None
    posts = []
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            sql = "SELECT b.id, b.title, b.content, b.created_at, b.updated_at, u.username FROM board b JOIN users u ON b.user_id = u.id"
            params = []
            if search_query:
                sql += " WHERE b.title LIKE %s OR b.content LIKE %s"
                params.extend([f"%{search_query}%", f"%{search_query}%"])
            sql += " ORDER BY b.created_at DESC"
            cursor.execute(sql, params)
            posts = cursor.fetchall()
    except Exception as e:
        print(f"데이터베이스 오류 (게시글 불러오기 및 검색): {e}")
        flash('게시판 글을 불러오는 데 실패했습니다. 잠시 후 다시 시도해주세요.', 'error')
    finally:
        if conn:
            conn.close()
    return render_template('board_list.html', posts=posts, username=session['username'], search_query=search_query)

@app.route('/board/write', methods=['GET', 'POST'])
def write_post():
    if 'loggedin' not in session:
        flash('게시글을 작성하려면 로그인해야 합니다.', 'error')
        return redirect(url_for('index'))

    if request.method == 'POST':
        title = request.form['title'].strip()
        content = request.form['content'].strip()
        user_id = session['id']

        if not title or not content:
            flash('제목과 내용은 비워둘 수 없습니다.', 'error')
            return redirect(url_for('write_post'))

        conn = None
        try:
            conn = get_db_connection()
            with conn.cursor() as cursor:
                sql = "INSERT INTO board (user_id, title, content) VALUES (%s, %s, %s)"
                cursor.execute(sql, (user_id, title, content))
                conn.commit()
                flash('게시글이 성공적으로 작성되었습니다!', 'success')
        except Exception as e:
            print(f"데이터베이스 오류 (게시글 작성): {e}")
            flash('게시글 작성에 실패했습니다. 잠시 후 다시 시도해주세요.', 'error')
        finally:
            if conn:
                conn.close()
        return redirect(url_for('board_list'))
    return render_template('write_post.html', username=session['username'])

@app.route('/board/view/<int:post_id>')
def view_post(post_id):
    if 'loggedin' not in session:
        flash('게시글을 보려면 로그인해야 합니다.', 'error')
        return redirect(url_for('index'))

    conn = None
    post = None
    comments = []
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            sql_post = "SELECT b.id, b.title, b.content, b.created_at, b.updated_at, b.user_id, u.username FROM board b JOIN users u ON b.user_id = u.id WHERE b.id = %s"
            cursor.execute(sql_post, (post_id,))
            post = cursor.fetchone()

            if not post:
                flash('게시글을 찾을 수 없습니다.', 'error')
                return redirect(url_for('board_list'))

            sql_comments = "SELECT c.id, c.content, c.created_at, u.username, c.user_id FROM comments c JOIN users u ON c.user_id = u.id WHERE c.board_id = %s ORDER BY c.created_at ASC"
            cursor.execute(sql_comments, (post_id,))
            comments = cursor.fetchall()
    except Exception as e:
        print(f"데이터베이스 오류 (게시글 조회): {e}")
        flash('게시글을 불러오는 데 실패했습니다. 잠시 후 다시 시도해주세요.', 'error')
    finally:
        if conn:
            conn.close()
    return render_template('view_post.html', post=post, comments=comments, username=session['username'])

@app.route('/board/edit/<int:post_id>', methods=['GET', 'POST'])
def edit_post(post_id):
    if 'loggedin' not in session:
        flash('게시글을 수정하려면 로그인해야 합니다.', 'error')
        return redirect(url_for('index'))

    conn = None
    post = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            sql = "SELECT id, title, content, user_id FROM board WHERE id=%s"
            cursor.execute(sql, (post_id,))
            post = cursor.fetchone()

            if not post:
                flash('게시글을 찾을 수 없습니다.', 'error')
                return redirect(url_for('board_list'))

            if post['user_id'] != session['id']:
                flash('이 게시글을 수정할 권한이 없습니다.', 'error')
                return redirect(url_for('view_post', post_id=post_id))

            if request.method == 'POST':
                title = request.form['title'].strip()
                content = request.form['content'].strip()

                if not title or not content:
                    flash('제목과 내용은 비워둘 수 없습니다.', 'error')
                    return redirect(url_for('edit_post', post_id=post_id))

                sql = "UPDATE board SET title = %s, content = %s WHERE id = %s"
                cursor.execute(sql, (title, content, post_id))
                conn.commit()
                flash('게시글이 성공적으로 수정되었습니다!', 'success')
                return redirect(url_for('view_post', post_id=post_id))
    except Exception as e:
        print(f"데이터베이스 오류 (게시글 수정): {e}")
        flash('게시글 수정에 실패했습니다. 잠시 후 다시 시도해주세요.', 'error')
    finally:
        if conn:
            conn.close()
    return render_template('edit_post.html', post=post, username=session['username'])

@app.route('/board/delete/<int:post_id>', methods=['POST'])
def delete_post(post_id):
    if 'loggedin' not in session:
        flash('게시글을 삭제하려면 로그인해야 합니다.', 'error')
        return redirect(url_for('index'))

    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            sql_check = "SELECT user_id FROM board WHERE id = %s"
            cursor.execute(sql_check, (post_id,))
            post_owner = cursor.fetchone()

            if not post_owner:
                flash('게시글을 찾을 수 없습니다.', 'error')
                return redirect(url_for('board_list'))

            if post_owner['user_id'] != session['id']:
                flash('이 게시글을 삭제할 권한이 없습니다.', 'error')
                return redirect(url_for('view_post', post_id=post_id))

            sql_delete = "DELETE FROM board WHERE id = %s"
            cursor.execute(sql_delete, (post_id,))
            conn.commit()
            flash('게시글이 성공적으로 삭제되었습니다!', 'success')
    except Exception as e:
        print(f"데이터베이스 오류 (게시글 삭제): {e}")
        flash('게시글 삭제에 실패했습니다. 잠시 후 다시 시도해주세요.', 'error')
    finally:
        if conn:
            conn.close()
    return redirect(url_for('board_list'))

@app.route('/comment/add/<int:post_id>', methods=['POST'])
def add_comment(post_id):
    if 'loggedin' not in session:
        flash('댓글을 작성하려면 로그인해야 합니다.', 'error')
        return redirect(url_for('index'))

    content = request.form['content'].strip()
    user_id = session['id']

    if not content:
        flash('댓글 내용은 비워둘 수 없습니다.', 'error')
        return redirect(url_for('view_post', post_id=post_id))

    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute("SELECT id FROM board WHERE id = %s", (post_id,))
            if not cursor.fetchone():
                flash('댓글을 달 게시글을 찾을 수 없습니다.', 'error')
                return redirect(url_for('board_list'))

            sql = "INSERT INTO comments (board_id, user_id, content) VALUES (%s, %s, %s)"
            cursor.execute(sql, (post_id, user_id, content))
            conn.commit()
            flash('댓글이 성공적으로 작성되었습니다!', 'success')
    except Exception as e:
        print(f"데이터베이스 오류 (댓글 작성): {e}")
        flash('댓글 작성에 실패했습니다. 잠시 후 다시 시도해주세요.', 'error')
    finally:
        if conn:
            conn.close()
    return redirect(url_for('view_post', post_id=post_id))

# --- 일기장 관련 라우트 ---
@app.route('/diary')
@app.route('/diary/<int:year>/<int:month>')
def diary_calendar(year=None, month=None):
    if 'loggedin' not in session:
        flash('일기장을 보려면 로그인해야 합니다.', 'error')
        return redirect(url_for('index'))

    today = datetime.now()
    if year is None:
        year = today.year
    if month is None:
        month = today.month

    if not (1 <= month <= 12 and 1900 <= year <= 2100):
        flash('유효하지 않은 연도 또는 월입니다.', 'error')
        return redirect(url_for('diary_calendar'))

    prev_month_date = (datetime(year, month, 1) - timedelta(days=1)).replace(day=1)
    next_month_date = (datetime(year, month, 1) + timedelta(days=31)).replace(day=1)
    prev_year, prev_month = prev_month_date.year, prev_month_date.month
    next_year, next_month = next_month_date.year, next_month_date.month

    cal = calendar.Calendar(firstweekday=6)
    month_days = cal.monthdayscalendar(year, month)
    user_id = session['id']
    diary_dates = set()
    conn = None

    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            sql = "SELECT DATE_FORMAT(entry_date, '%%Y-%%m-%%d') AS entry_date_str FROM diaries WHERE user_id = %s AND YEAR(entry_date) = %s AND MONTH(entry_date) = %s"
            cursor.execute(sql, (user_id, year, month))
            for row in cursor.fetchall():
                diary_dates.add(row['entry_date_str'])
    except Exception as e:
        print(f"DEBUG: 일기 데이터를 불러오는 데 오류 발생: {e}")
        flash('일기 데이터를 불러오는 데 실패했습니다.', 'error')
    finally:
        if conn:
            conn.close()

    return render_template('diary_calendar.html', year=year, month=month, month_name=datetime(year, month, 1).strftime('%B'), month_days=month_days, diary_dates=diary_dates, prev_year=prev_year, prev_month=prev_month, next_year=next_year, next_month=next_month, current_day=today.day if today.year == year and today.month == month else None, today=today, username=session['username'])

@app.route('/diary/entry/<string:date_str>', methods=['GET', 'POST'])
def diary_entry(date_str):
    if 'loggedin' not in session:
        flash('일기를 작성/조회하려면 로그인해야 합니다.', 'error')
        return redirect(url_for('index'))

    user_id = session['id']
    entry_date = None
    try:
        entry_date = datetime.strptime(date_str, '%Y-%m-%d').date()
    except ValueError:
        flash('유효하지 않은 날짜 형식입니다.', 'error')
        return redirect(url_for('diary_calendar'))

    diary = None
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            sql = "SELECT id, title, content, DATE_FORMAT(entry_date, '%%Y-%%m-%%d') AS entry_date_str FROM diaries WHERE user_id = %s AND entry_date = %s"
            cursor.execute(sql, (user_id, entry_date))
            diary = cursor.fetchone()

            if request.method == 'POST':
                title = request.form.get('title', '').strip()
                content = request.form['content'].strip()

                if not content:
                    flash('일기 내용은 비워둘 수 없습니다.', 'error')
                    return redirect(url_for('diary_entry', date_str=date_str))

                if diary:
                    sql = "UPDATE diaries SET title = %s, content = %s WHERE id = %s AND user_id = %s"
                    cursor.execute(sql, (title, content, diary['id'], user_id))
                    flash('일기가 성공적으로 수정되었습니다!', 'success')
                else:
                    sql = "INSERT INTO diaries (user_id, entry_date, title, content) VALUES (%s, %s, %s, %s)"
                    cursor.execute(sql, (user_id, entry_date, title, content))
                    flash('일기가 성공적으로 작성되었습니다!', 'success')
                
                conn.commit()
                return redirect(url_for('diary_calendar', year=entry_date.year, month=entry_date.month))
    except Exception as e:
        print(f"DEBUG: diary_entry에서 데이터베이스 오류: {e}")
        flash('일기 처리 중 오류가 발생했습니다.', 'error')
    finally:
        if conn:
            conn.close()
            
    return render_template('diary_entry.html', diary=diary, date_str=date_str, username=session['username'])

# --- To-Do List 관련 라우트 ---
@app.route('/todos')
def todos_list():
    if 'loggedin' not in session:
        flash('To-Do List를 보려면 로그인해야 합니다.', 'error')
        return redirect(url_for('index'))

    user_id = session['id']
    status_filter = request.args.get('status', 'all').strip()
    search_query = request.args.get('query', '').strip()
    conn = None
    todos = []

    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            sql = "SELECT id, task, DATE_FORMAT(due_date, '%%Y-%%m-%%d') AS due_date, status, created_at FROM todos WHERE user_id = %s"
            params = [user_id]
            
            if status_filter != 'all':
                sql += " AND status = %s"
                params.append(status_filter)
            
            if search_query:
                sql += " AND task LIKE %s"
                params.append(f"%{search_query}%")
                
            sql += " ORDER BY created_at DESC"
            cursor.execute(sql, params)
            todos = cursor.fetchall()
    except Exception as e:
        print(f"DEBUG: To-Do 목록 불러오기 오류: {e}")
        flash('To-Do 목록을 불러오는 데 실패했습니다. 잠시 후 다시 시도해주세요.', 'error')
    finally:
        if conn:
            conn.close()

    return render_template('todos_list.html', todos=todos, username=session['username'], status_filter=status_filter, search_query=search_query, all_statuses=['미완료', '진행중', '완료', '기간연장'])

@app.route('/todos/add', methods=['POST'])
def add_todo():
    if 'loggedin' not in session:
        flash('To-Do 항목을 추가하려면 로그인해야 합니다.', 'error')
        return redirect(url_for('index'))

    user_id = session['id']
    task = request.form['task'].strip()
    due_date_str = request.form.get('due_date', '').strip()
    status = request.form.get('status', '미완료').strip()

    if not task:
        flash('할 일 내용을 비워둘 수 없습니다.', 'error')
        return redirect(url_for('todos_list'))

    due_date = None
    if due_date_str:
        try:
            due_date = datetime.strptime(due_date_str, '%Y-%m-%d').date()
        except ValueError:
            flash('유효하지 않은 마감일 형식입니다.', 'error')
            return redirect(url_for('todos_list'))

    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            sql = "INSERT INTO todos (user_id, task, due_date, status) VALUES (%s, %s, %s, %s)"
            cursor.execute(sql, (user_id, task, due_date, status))
            conn.commit()
            flash('To-Do 항목이 성공적으로 추가되었습니다!', 'success')
    except Exception as e:
        print(f"DEBUG: To-Do 항목 추가 오류: {e}")
        flash('To-Do 항목 추가에 실패했습니다. 잠시 후 다시 시도해주세요.', 'error')
    finally:
        if conn:
            conn.close()
            
    return redirect(url_for('todos_list'))

@app.route('/todos/update_status/<int:todo_id>/<string:new_status>', methods=['POST'])
def update_todo_status(todo_id, new_status):
    if 'loggedin' not in session:
        flash('To-Do 항목 상태를 변경하려면 로그인해야 합니다.', 'error')
        return redirect(url_for('index'))

    user_id = session['id']
    valid_statuses = ['미완료', '진행중', '완료', '기간연장']
    
    if new_status not in valid_statuses:
        flash('유효하지 않은 To-Do 상태입니다.', 'error')
        return redirect(url_for('todos_list'))

    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            sql_check = "SELECT id FROM todos WHERE id = %s AND user_id = %s"
            cursor.execute(sql_check, (todo_id, user_id))
            if not cursor.fetchone():
                flash('To-Do 항목을 찾을 수 없거나 권한이 없습니다.', 'error')
                return redirect(url_for('todos_list'))

            sql = "UPDATE todos SET status = %s WHERE id = %s AND user_id = %s"
            cursor.execute(sql, (new_status, todo_id, user_id))
            conn.commit()
            flash('To-Do 항목 상태가 성공적으로 업데이트되었습니다!', 'success')
    except Exception as e:
        print(f"DEBUG: To-Do 상태 업데이트 오류: {e}")
        flash('To-Do 항목 상태 업데이트에 실패했습니다. 잠시 후 다시 시도해주세요.', 'error')
    finally:
        if conn:
            conn.close()
            
    return redirect(url_for('todos_list'))

@app.route('/todos/delete/<int:todo_id>', methods=['POST'])
def delete_todo(todo_id):
    if 'loggedin' not in session:
        flash('To-Do 항목을 삭제하려면 로그인해야 합니다.', 'error')
        return redirect(url_for('index'))

    user_id = session['id']
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            sql_check = "SELECT id FROM todos WHERE id = %s AND user_id = %s"
            cursor.execute(sql_check, (todo_id, user_id))
            if not cursor.fetchone():
                flash('To-Do 항목을 찾을 수 없거나 권한이 없습니다.', 'error')
                return redirect(url_for('todos_list'))

            sql = "DELETE FROM todos WHERE id = %s AND user_id = %s"
            cursor.execute(sql, (todo_id, user_id))
            conn.commit()
            flash('To-Do 항목이 성공적으로 삭제되었습니다!', 'success')
    except Exception as e:
        print(f"DEBUG: To-Do 항목 삭제 오류: {e}")
        flash('To-Do 항목 삭제에 실패했습니다. 잠시 후 다시 시도해주세요.', 'error')
    finally:
        if conn:
            conn.close()
            
    return redirect(url_for('todos_list'))

@app.route('/todos/reschedule/<int:todo_id>')
@app.route('/todos/reschedule/<int:todo_id>/<int:year>/<int:month>')
def reschedule_todo_calendar(todo_id, year=None, month=None):
    if 'loggedin' not in session:
        flash('To-Do 항목 마감일을 재조정하려면 로그인해야 합니다.', 'error')
        return redirect(url_for('index'))

    user_id = session['id']
    todo_item = None
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            sql = "SELECT id, task, DATE_FORMAT(due_date, '%%Y-%%m-%%d') AS due_date, status FROM todos WHERE id = %s AND user_id = %s"
            cursor.execute(sql, (todo_id, user_id))
            todo_item = cursor.fetchone()
            if not todo_item:
                flash('To-Do 항목을 찾을 수 없거나 권한이 없습니다.', 'error')
                return redirect(url_for('todos_list'))
    except Exception as e:
        print(f"DEBUG: Error fetching todo item for reschedule: {e}")
        flash('To-Do 항목 정보를 불러오는 데 실패했습니다.', 'error')
        return redirect(url_for('todos_list'))
    finally:
        if conn:
            conn.close()

    today = datetime.now()
    if year is None:
        year = today.year
    if month is None:
        month = today.month

    if not (1 <= month <= 12 and 1900 <= year <= 2100):
        flash('유효하지 않은 연도 또는 월입니다.', 'error')
        return redirect(url_for('reschedule_todo_calendar', todo_id=todo_id))

    prev_month_date = (datetime(year, month, 1) - timedelta(days=1)).replace(day=1)
    next_month_date = (datetime(year, month, 1) + timedelta(days=31)).replace(day=1)
    prev_year, prev_month = prev_month_date.year, prev_month_date.month
    next_year, next_month = next_month_date.year, next_month_date.month

    cal = calendar.Calendar(firstweekday=6)
    month_days = cal.monthdayscalendar(year, month)

    return render_template('todos_reschedule.html', todo_item=todo_item, year=year, month=month, month_name=datetime(year, month, 1).strftime('%B'), month_days=month_days, prev_year=prev_year, prev_month=prev_month, next_year=next_year, next_month=next_month, current_day=today.day if today.year == year and today.month == month else None, today=today, username=session['username'])

@app.route('/todos/set_due_date/<int:todo_id>', methods=['POST'])
def set_new_due_date(todo_id):
    if 'loggedin' not in session:
        flash('To-Do 항목 마감일을 설정하려면 로그인해야 합니다.', 'error')
        return redirect(url_for('index'))

    user_id = session['id']
    new_due_date_str = request.form.get('new_due_date').strip()

    if not new_due_date_str:
        flash('새로운 마감일을 선택해야 합니다.', 'error')
        return redirect(url_for('todos_list'))

    new_due_date = None
    try:
        new_due_date = datetime.strptime(new_due_date_str, '%Y-%m-%d').date()
    except ValueError:
        flash('유효하지 않은 날짜 형식입니다.', 'error')
        return redirect(url_for('todos_list'))

    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            sql_check = "SELECT id, status FROM todos WHERE id = %s AND user_id = %s"
            cursor.execute(sql_check, (todo_id, user_id))
            item_data = cursor.fetchone()

            if not item_data:
                flash('To-Do 항목을 찾을 수 없거나 권한이 없습니다.', 'error')
                return redirect(url_for('todos_list'))

            new_status_after_reschedule = item_data['status']
            if item_data['status'] == '완료':
                new_status_after_reschedule = '미완료'
            elif item_data['status'] == '기간연장':
                new_status_after_reschedule = '기간연장'
            else:
                new_status_after_reschedule = '진행중'

            sql_update = "UPDATE todos SET due_date = %s, status = %s WHERE id = %s AND user_id = %s"
            cursor.execute(sql_update, (new_due_date, new_status_after_reschedule, todo_id, user_id))
            conn.commit()
            flash(f'할 일의 마감일이 {new_due_date_str}으로 성공적으로 재조정되었습니다!', 'success')
    except Exception as e:
        print(f"DEBUG: To-Do 마감일 설정 오류: {e}")
        flash('마감일 재조정에 실패했습니다. 잠시 후 다시 시도해주세요.', 'error')
    finally:
        if conn:
            conn.close()
            
    return redirect(url_for('todos_list'))

# --- 학습 콘텐츠 관련 라우트 ---
@app.route('/study')
def study_list():
    if 'loggedin' not in session:
        flash('학습 콘텐츠를 보려면 로그인해야 합니다.', 'error')
        return redirect(url_for('index'))

    conn = None
    subjects = []
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute("SELECT id, name FROM subjects ORDER BY name ASC")
            subjects = cursor.fetchall()
    except Exception as e:
        print(f"데이터베이스 오류 (과목 목록 불러오기): {e}")
        flash('과목 목록을 불러오는 데 실패했습니다.', 'error')
    finally:
        if conn:
            conn.close()
            
    return render_template('study_list.html', subjects=subjects, username=session['username'])

@app.route('/study/<int:subject_id>')
def subject_detail(subject_id):
    if 'loggedin' not in session:
        flash('학습 콘텐츠를 보려면 로그인해야 합니다.', 'error')
        return redirect(url_for('index'))

    conn = None
    subject = None
    theory_contents = []
    lab_contents = []

    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute("SELECT id, name FROM subjects WHERE id = %s", (subject_id,))
            subject = cursor.fetchone()
            
            if not subject:
                flash('존재하지 않는 과목입니다.', 'error')
                return redirect(url_for('study_list'))

            sql_theory = "SELECT id, title, created_at, is_active FROM contents WHERE subject_id = %s AND content_type = '이론' ORDER BY created_at ASC"
            cursor.execute(sql_theory, (subject_id,))
            theory_contents = cursor.fetchall()

            sql_lab = "SELECT id, title, created_at, is_active FROM contents WHERE subject_id = %s AND content_type = '실습' ORDER BY created_at ASC"
            cursor.execute(sql_lab, (subject_id,))
            lab_contents = cursor.fetchall()
    except Exception as e:
        print(f"데이터베이스 오류 (콘텐츠 목록 불러오기): {e}")
        flash('콘텐츠 목록을 불러오는 데 실패했습니다.', 'error')
    finally:
        if conn:
            conn.close()
            
    return render_template('subject_detail.html', subject=subject, theory_contents=theory_contents, lab_contents=lab_contents, username=session['username'])

@app.route('/content/<int:content_id>')
def view_content(content_id):
    if 'loggedin' not in session:
        flash('콘텐츠를 보려면 로그인해야 합니다.', 'error')
        return redirect(url_for('index'))

    conn = None
    content = None
    subject_id_for_redirect = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            sql = """
            SELECT c.id, c.title, c.body, c.content_type, c.created_at, c.subject_id, c.is_active, s.name as subject_name
            FROM contents c
            JOIN subjects s ON c.subject_id = s.id
            WHERE c.id = %s
            """
            cursor.execute(sql, (content_id,))
            content = cursor.fetchone()

            if not content:
                flash('존재하지 않는 콘텐츠입니다.', 'error')
                return redirect(url_for('study_list'))

            subject_id_for_redirect = content['subject_id']

            if not content['is_active'] and session.get('username') not in ['kevin', 'kwangjin']:
                flash('아직 활성화되지 않은 콘텐츠입니다. 관리자에게 문의하세요.', 'error')
                return redirect(url_for('subject_detail', subject_id=subject_id_for_redirect))
    except Exception as e:
        print(f"데이터베이스 오류 (콘텐츠 조회): {e}")
        flash('콘텐츠를 불러오는 데 실패했습니다.', 'error')
        if subject_id_for_redirect:
            return redirect(url_for('subject_detail', subject_id=subject_id_for_redirect))
        return redirect(url_for('study_list'))
    finally:
        if conn:
            conn.close()
            
    return render_template('view_content.html', content=content, username=session['username'])

@app.route('/content/toggle_status/<int:content_id>', methods=['POST'])
def toggle_content_status(content_id):
    if not is_admin():
        flash('이 작업을 수행할 권한이 없습니다.', 'error')
        return redirect(request.referrer or url_for('study_list'))

    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute("SELECT subject_id FROM contents WHERE id = %s", (content_id,))
            content = cursor.fetchone()
            if not content:
                flash('존재하지 않는 콘텐츠입니다.', 'error')
                return redirect(url_for('study_list'))

            subject_id = content['subject_id']
            sql_update = "UPDATE contents SET is_active = NOT is_active WHERE id = %s"
            cursor.execute(sql_update, (content_id,))
            conn.commit()
            flash('콘텐츠 상태가 성공적으로 변경되었습니다.', 'success')
            return redirect(url_for('subject_detail', subject_id=subject_id))
    except Exception as e:
        print(f"데이터베이스 오류 (콘텐츠 상태 변경): {e}")
        flash('콘텐츠 상태 변경에 실패했습니다.', 'error')
        return redirect(request.referrer or url_for('study_list'))
    finally:
        if conn:
            conn.close()

# --- 관리자 페이지 관련 라우트 ---
@app.route('/admin')
def admin_dashboard():
    if not is_admin():
        flash('접근 권한이 없습니다.', 'error')
        return redirect(url_for('index'))
    return render_template('admin_dashboard.html', username=session['username'])

@app.route('/admin/add_content', methods=['GET', 'POST'])
def add_content():
    if not is_admin():
        flash('접근 권한이 없습니다.', 'error')
        return redirect(url_for('index'))

    conn = None
    try:
        conn = get_db_connection()
        if request.method == 'POST':
            subject_id = request.form['subject_id']
            content_type = request.form['content_type']
            title = request.form['title'].strip()
            body = request.form['body'].strip()

            if not all([subject_id, content_type, title, body]):
                flash('모든 필드를 채워주세요.', 'error')
            else:
                with conn.cursor() as cursor:
                    sql = "INSERT INTO contents (subject_id, content_type, title, body) VALUES (%s, %s, %s, %s)"
                    cursor.execute(sql, (subject_id, content_type, title, body))
                    conn.commit()
                    flash('새로운 콘텐츠가 성공적으로 등록되었습니다.', 'success')
                    return redirect(url_for('admin_dashboard'))

        with conn.cursor() as cursor:
            cursor.execute("SELECT id, name FROM subjects ORDER BY name ASC")
            subjects = cursor.fetchall()
        return render_template('add_content.html', subjects=subjects, username=session['username'])
    except Exception as e:
        print(f"관리자 콘텐츠 추가 오류: {e}")
        flash('콘텐츠 추가 중 오류가 발생했습니다.', 'error')
        return redirect(url_for('admin_dashboard'))
    finally:
        if conn:
            conn.close()

@app.route('/admin/subjects', methods=['GET', 'POST'])
def manage_subjects():
    if not is_admin():
        flash('접근 권한이 없습니다.', 'error')
        return redirect(url_for('index'))

    conn = None
    try:
        conn = get_db_connection()
        if request.method == 'POST':
            name = request.form['name'].strip()
            if name:
                with conn.cursor() as cursor:
                    cursor.execute("SELECT id FROM subjects WHERE name = %s", (name,))
                    if cursor.fetchone():
                        flash('이미 존재하는 과목 이름입니다.', 'error')
                    else:
                        cursor.execute("INSERT INTO subjects (name) VALUES (%s)", (name,))
                        conn.commit()
                        flash('새로운 과목이 성공적으로 등록되었습니다.', 'success')
            else:
                flash('과목 이름을 입력해주세요.', 'error')
            return redirect(url_for('manage_subjects'))

        with conn.cursor() as cursor:
            cursor.execute("SELECT id, name FROM subjects ORDER BY name ASC")
            subjects = cursor.fetchall()
        return render_template('manage_subjects.html', subjects=subjects, username=session['username'])
    except Exception as e:
        print(f"과목 관리 페이지 오류: {e}")
        flash('과목 관리 페이지를 로드하는 중 오류가 발생했습니다.', 'error')
        return redirect(url_for('admin_dashboard'))
    finally:
        if conn:
            conn.close()

@app.route('/admin/edit_subject/<int:subject_id>', methods=['GET', 'POST'])
def edit_subject(subject_id):
    if not is_admin():
        flash('접근 권한이 없습니다.', 'error')
        return redirect(url_for('index'))

    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            if request.method == 'POST':
                new_name = request.form['name'].strip()
                if not new_name:
                    flash('과목 이름은 비워둘 수 없습니다.', 'error')
                else:
                    cursor.execute("SELECT id FROM subjects WHERE name = %s AND id != %s", (new_name, subject_id))
                    if cursor.fetchone():
                        flash('이미 존재하는 과목 이름입니다.', 'error')
                    else:
                        cursor.execute("UPDATE subjects SET name = %s WHERE id = %s", (new_name, subject_id))
                        conn.commit()
                        flash('과목 이름이 성공적으로 수정되었습니다.', 'success')
                        return redirect(url_for('manage_subjects'))

            cursor.execute("SELECT id, name FROM subjects WHERE id = %s", (subject_id,))
            subject = cursor.fetchone()
            if not subject:
                flash('존재하지 않는 과목입니다.', 'error')
                return redirect(url_for('manage_subjects'))
            return render_template('edit_subject.html', subject=subject, username=session['username'])
    except Exception as e:
        print(f"과목 수정 오류: {e}")
        flash('과목 수정 중 오류가 발생했습니다.', 'error')
        return redirect(url_for('manage_subjects'))
    finally:
        if conn:
            conn.close()

@app.route('/admin/delete_subject/<int:subject_id>', methods=['POST'])
def delete_subject(subject_id):
    if not is_admin():
        flash('접근 권한이 없습니다.', 'error')
        return redirect(url_for('index'))

    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute("DELETE FROM subjects WHERE id = %s", (subject_id,))
            conn.commit()
            flash('과목 및 관련 콘텐츠가 모두 삭제되었습니다.', 'success')
    except Exception as e:
        print(f"과목 삭제 오류: {e}")
        flash('과목 삭제 중 오류가 발생했습니다.', 'error')
    finally:
        if conn:
            conn.close()
    return redirect(url_for('manage_subjects'))

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
