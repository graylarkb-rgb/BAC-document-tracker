from flask import Flask, abort, render_template, jsonify, session, current_app, request, redirect, flash, url_for
from werkzeug.security import check_password_hash, generate_password_hash
from database import get_db_connection, init_db
from datetime import datetime
from flask import send_file
from werkzeug.utils import secure_filename
import sqlite3
import os

# Adjust these for your app
UPLOAD_FOLDER = os.path.join("static", "uploads", "transmitting_documents")
ALLOWED_EXTENSIONS = {"pdf", "png", "jpg", "jpeg", "doc", "docx", "xls", "xlsx"}

def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def ensure_upload_dir():
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__)
app.secret_key = "super_secret_key"  # change later

init_db()

# ===== Helper function to log audit trail =====
def log_audit(username, office, action):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO audit_trail (username, office, action, date_time)
        VALUES (?, ?, ?, ?)
    """, (username, office, action, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    conn.close()


# =========================
# AUTHENTICATION
# =========================
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        ).fetchone()
        conn.close()

        if user and check_password_hash(user['password'], password):
            # ✅ use ONE consistent session key
            session['user'] = user['username']
            session['role'] = user['role']
            session['office'] = user['office']

            # Log login action
            log_audit(user['username'], user['office'], f"{user['username']} Logged In")

            # ✅ redirect to correct dashboard based on role + office
            if (user['role'] or "").lower() == "admin":
                return redirect(url_for('admin_dashboard'))

            # Non-admin users -> office dashboards
            office = (user['office'] or "").upper()

            if office == "OME":
                return redirect(url_for("ome_dashboard"))

            # fallback for other offices not yet created
            return redirect(url_for("user_dashboard"))

        else:
            flash("Invalid username or password", "error")

    return render_template('login.html')

@app.route('/logout')
def logout():
    username = session.get('user')  # ✅ fixed
    office = session.get('office', '')

    # ===== Log logout action =====
    if username:
        log_audit(username, office, f"{username} Logged Out")

    session.clear()
    return redirect('/')


# =========================
# DASHBOARDS
# =========================
@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        flash("Please login first.", "error")
        return redirect(url_for('login'))

    role = (session.get('role') or "").lower()
    if role == "admin":
        return redirect(url_for('admin_dashboard'))

    office = (session.get('office') or "").upper()
    if office == "OME":
        return redirect(url_for("ome_dashboard"))

    return redirect(url_for('user_dashboard'))

@app.route('/admin/dashboard')
def admin_dashboard():
    # ✅ must be logged in
    if 'user' not in session:
        flash("Please login first.", "error")
        return redirect(url_for('login'))

    # ✅ block non-admin users
    if (session.get('role') or "").lower() != "admin":
        flash("Access denied.", "error")
        return redirect(url_for('user_dashboard'))

    return render_template(
        'admin/dashboard.html',
        user=session.get('user'),
        role=session.get('role'),
        office=session.get('office')
    )

@app.route("/user/dashboard")
def user_dashboard():
    if "user" not in session:
        flash("Please login first.", "error")
        return redirect(url_for("login"))

    office = (session.get("office") or "").upper().strip()

    if office == "OME":
        return redirect("/ome/dashboard")   # ✅ direct path (no endpoint name issues)
    elif office == "MBO":
        return redirect("/mbo/dashboard")   # ✅ direct path

    flash("Access denied.", "error")
    return redirect("/dashboard")

# =========================
# USER MANAGEMENT
# =========================
@app.route('/manage-users')
def manage_users():
    if 'user' not in session:
        flash("Please login first.", "error")
        return redirect(url_for('login'))

    if (session.get('role') or "").lower() != 'admin':
        return "Access denied", 403

    conn = get_db_connection()
    users = conn.execute(
        "SELECT id, name, username, office, role, status FROM users"
    ).fetchall()
    conn.close()

    return render_template('admin/manage_users.html', users=users)

@app.route('/edit-users')
def edit_users():
    search_query = request.args.get('q', '')

    conn = get_db_connection()
    if search_query:
        users = conn.execute(
            "SELECT * FROM users WHERE name LIKE ? OR username LIKE ?",
            ('%' + search_query + '%', '%' + search_query + '%')
        ).fetchall()
    else:
        users = conn.execute("SELECT * FROM users").fetchall()
    conn.close()

    return render_template('admin/edit_users.html', users=users, message=None)


# =========================
# ADD USER (FIXES BuildError)
# =========================
@app.route('/add-user', methods=['POST'])
def add_user():
    # ✅ login check (consistent)
    if 'user' not in session:
        flash("Please login first.", "error")
        return redirect(url_for('login'))

    # ✅ admin only (case-insensitive)
    if (session.get('role') or "").lower() != 'admin':
        return "Access denied", 403

    # ===== New user data =====
    name = request.form['name']
    new_username = request.form['username']
    office = request.form['office']
    password = request.form['password']
    role = request.form['role']
    status = 'Active'

    hashed_password = generate_password_hash(password)

    # ===== Admin info =====
    admin_username = session.get('user')          # ✅ fixed
    admin_office = session.get('office', '')
    date_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    conn = get_db_connection()
    try:
        # ===== Insert new user =====
        conn.execute("""
            INSERT INTO users (name, username, password, office, status, role)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (name, new_username, hashed_password, office, status, role))

        # ===== Insert audit trail =====
        action = f"{admin_username} added a new user {name} to {office}"
        conn.execute("""
            INSERT INTO audit_trail (username, office, action, date_time)
            VALUES (?, ?, ?, ?)
        """, (admin_username, admin_office, action, date_time))

        conn.commit()
        flash("User added successfully!", "success")

    except sqlite3.IntegrityError:
        flash("Username already exists!", "error")

    finally:
        conn.close()

    return redirect(url_for('manage_users'))

@app.route('/update-user', methods=['POST'])
def update_user():
    if 'user' not in session:
        return jsonify({
            "status": "error",
            "message": "Session expired. Please login again."
        }), 401

    if (session.get('role') or "").lower() != 'admin':
        return jsonify({
            "status": "error",
            "message": "Access denied"
        }), 403

    user_id = request.form['user_id']
    new_name = request.form['name']
    new_username = request.form['username']
    new_office = request.form['office']
    new_password = request.form.get('password')  # optional

    admin_username = session['user']           # ✅ fixed
    admin_office = session.get('office', '')
    date_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    conn = get_db_connection()

    old_user = conn.execute("""
        SELECT name, username, office
        FROM users
        WHERE id = ?
    """, (user_id,)).fetchone()

    if not old_user:
        conn.close()
        return jsonify({"status": "error", "message": "User not found"}), 404

    if new_password:
        conn.execute("""
            UPDATE users
            SET name=?, username=?, office=?, password=?
            WHERE id=?
        """, (
            new_name,
            new_username,
            new_office,
            generate_password_hash(new_password),
            user_id
        ))
    else:
        conn.execute("""
            UPDATE users
            SET name=?, username=?, office=?
            WHERE id=?
        """, (new_name, new_username, new_office, user_id))

    audit_actions = []

    if old_user['name'] != new_name:
        audit_actions.append(
            f"{admin_username} edited the name {old_user['name']} into {new_name}"
        )

    if old_user['username'] != new_username:
        audit_actions.append(
            f"{admin_username} edited the username {old_user['username']} into {new_username}"
        )

    if old_user['office'] != new_office:
        audit_actions.append(
            f"{admin_username} edited the office {old_user['office']} into {new_office}"
        )

    if new_password:
        audit_actions.append(
            f"{admin_username} edited the password of {old_user['name']}"
        )

    for action in audit_actions:
        conn.execute("""
            INSERT INTO audit_trail (username, office, action, date_time)
            VALUES (?, ?, ?, ?)
        """, (admin_username, admin_office, action, date_time))

    conn.commit()
    conn.close()

    return jsonify({
        "status": "success",
        "message": "User updated successfully!"
    })

@app.route('/delete-user', methods=['POST'])
def delete_user():
    user_id = request.form.get('user_id')
    if not user_id:
        return jsonify({"status": "error", "message": "User ID missing"}), 400

    # ✅ Must be logged in
    if 'user' not in session:
        return jsonify({"status": "error", "message": "Session expired. Please login again."}), 401

    # ✅ Admin only
    if (session.get('role') or "").lower() != "admin":
        return jsonify({"status": "error", "message": "Access denied"}), 403

    admin_username = session.get('user')   # ✅ fixed
    admin_office = session.get('office', '')

    conn = get_db_connection()
    cursor = conn.cursor()

    # Fetch the user info before deleting
    cursor.execute("SELECT username FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    if not user:
        conn.close()
        return jsonify({"status": "error", "message": "User not found"}), 404

    target_username = user[0]

    # Delete the user
    cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))

    # Audit trail
    action_text = f"{admin_username} deleted user {target_username}"
    cursor.execute("""
        INSERT INTO audit_trail (username, office, action, date_time)
        VALUES (?, ?, ?, ?)
    """, (
        admin_username,
        admin_office,
        action_text,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))

    conn.commit()
    conn.close()

    return jsonify({"status": "success", "message": "User deleted successfully!"})


# =========================
# AUDIT TRAIL
# =========================

# ===== Render the Audit Trail Page =====
@app.route("/audit-trail")
def audit_trail_page():
    return render_template("admin/audit_trail.html")

# ===== API endpoint to fetch audit trail data =====
@app.route("/audit-trail-data")
def audit_trail_data():
    conn = get_db_connection()
    rows = conn.execute("SELECT * FROM audit_trail ORDER BY id DESC").fetchall()
    conn.close()

    data = [
        {
            "id": row["id"],
            "username": row["username"],
            "office": row["office"],
            "action": row["action"],
            "date_time": row["date_time"]
        } for row in rows
    ]

    return jsonify(data)


# =========================
# SETUP SIGNATORIES
# =========================
@app.route("/setup-signatories")
def setup_signatories():
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row  # allow access by column name in template
    cursor = conn.cursor()
    cursor.execute("SELECT id, name, office_department, designation, remarks FROM signatories")
    signatories = cursor.fetchall()
    conn.close()
    return render_template("admin/setup_signatories.html", signatories=signatories)

@app.route('/add_signatory', methods=['POST'])
def add_signatory():
    # Get form data
    name = request.form.get('name')
    office_department = request.form.get('office')
    designation = request.form.get('designation')

    # ✅ Who added the signatory (FIXED)
    added_by = session.get('user', 'Unknown')
    admin_office = session.get('office')

    # Timestamp
    date_added = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Build remarks
    remarks = f"Added on {date_added} by {added_by}"

    conn = get_db_connection()
    cursor = conn.cursor()

    # Insert into signatories table
    cursor.execute("""
        INSERT INTO signatories
        (name, office_department, designation, date_added, added_by, edited_by, remarks)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        name,
        office_department,
        designation,
        date_added,
        added_by,
        None,
        remarks
    ))

    # ✅ AUDIT TRAIL ENTRY
    action_text = f"{added_by} setup a new signatories for {name} - {office_department}"

    cursor.execute("""
        INSERT INTO audit_trail (username, office, action, date_time)
        VALUES (?, ?, ?, ?)
    """, (
        added_by,
        admin_office,
        action_text,
        date_added
    ))

    conn.commit()
    conn.close()

    flash("Signatory Successfully Added!", "success")
    return redirect(url_for('setup_signatories'))

@app.route('/edit_signatory/<int:id>', methods=['POST'])
def edit_signatory(id):
    # ✅ Use actual logged-in user (NOT hardcoded)
    username = session.get('user', 'Unknown')
    admin_office = session.get('office')

    name = request.form['name']
    office = request.form['office']
    designation = request.form['designation']

    date_edited = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    remarks = f"Last updated {date_edited} by {username}"

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    # ✅ Update signatory record
    cursor.execute("""
        UPDATE signatories
        SET name = ?,
            office_department = ?,
            designation = ?,
            edited_by = ?,
            date_edited = ?,
            remarks = ?
        WHERE id = ?
    """, (name, office, designation, username, date_edited, remarks, id))

    # ✅ AUDIT TRAIL ENTRY
    action_text = f"{username} Edited the Signatory data of {name} - {office}"

    cursor.execute("""
        INSERT INTO audit_trail (username, office, action, date_time)
        VALUES (?, ?, ?, ?)
    """, (
        username,
        admin_office,
        action_text,
        date_edited
    ))

    conn.commit()
    conn.close()

    flash("Signatory updated successfully!", "success")
    return redirect(url_for('setup_signatories'))

@app.route('/delete_signatory/<int:id>', methods=['POST'])
def delete_signatory(id):
    # ✅ Logged-in user
    username = session.get('user', 'Unknown')
    admin_office = session.get('office')

    conn = get_db_connection()
    cursor = conn.cursor()

    # ✅ Get signatory details BEFORE deleting (for audit trail)
    cursor.execute("""
        SELECT name, office_department
        FROM signatories
        WHERE id = ?
    """, (id,))
    row = cursor.fetchone()

    if row:
        signatory_name = row['name']
        signatory_office = row['office_department']
    else:
        signatory_name = "Unknown"
        signatory_office = "Unknown"

    # ✅ Delete the signatory
    cursor.execute("DELETE FROM signatories WHERE id = ?", (id,))

    # ✅ AUDIT TRAIL ENTRY
    date_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    action_text = f"{username} deleted the signatory for {signatory_name} - {signatory_office}"

    cursor.execute("""
        INSERT INTO audit_trail (username, office, action, date_time)
        VALUES (?, ?, ?, ?)
    """, (
        username,
        admin_office,
        action_text,
        date_time
    ))

    conn.commit()
    conn.close()

    flash("Signatory successfully deleted.", "success")
    return redirect(url_for('setup_signatories'))



# =========================
# DOCUMENTS
# =========================
@app.route("/documents")
def documents():
    conn = get_db_connection()
    issued = conn.execute("""
        SELECT 
            control_no,
            program,
            amount,
            code,
            office,
            issued_by,
            issued_date
    
        FROM issued_control_no
        ORDER BY issued_date DESC
    """).fetchall()
    conn.close()

    return render_template("admin/documents.html", issued=issued)

@app.route('/assign-control-no', methods=['POST'])
def assign_control_no():
    if 'user' not in session:
        flash("You must be logged in to issue a control number.", "error")
        return redirect(url_for('login'))

    control_no = request.form.get('control_no', '').strip()
    amount = request.form.get('amount', '').strip()  # ✅ keep commas
    office = request.form.get('office', '').strip()
    program = request.form.get('program', '').strip()
    code = request.form.get('code', '').strip()
    source_of_fund = request.form.get('source_of_fund', '').strip()

    if not all([control_no, amount, office, program, code, source_of_fund]):
        flash("Please fill out all fields.", "error")
        return redirect(url_for('documents'))

    issued_by = session.get('user', 'Unknown')
    issued_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = get_db_connection()
    try:
        conn.execute("""
            INSERT INTO issued_control_no
            (control_no, amount, office, program, code, source_of_fund, issued_date, issued_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (control_no, amount, office, program, code, source_of_fund, issued_date, issued_by))

        # ✅ AUDIT TRAIL ENTRY
        admin_office = session.get('office')
        action_text = f"{issued_by} Issued control number {control_no}-{program} to {office}"

        conn.execute("""
            INSERT INTO audit_trail (username, office, action, date_time)
            VALUES (?, ?, ?, ?)
        """, (issued_by, admin_office, action_text, issued_date))

        conn.commit()
        flash("Control number issued successfully.", "success")

    except Exception as e:
        conn.rollback()
        flash(f"Error issuing control number: {e}", "error")
    finally:
        conn.close()

    return redirect(url_for('documents'))

@app.route('/edit-document')
def edit_document():
    return render_template('admin/edit_documents.html')

@app.route('/edit-documents')
def edit_documents():
    conn = get_db_connection()
    rows = conn.execute("""
        SELECT
            control_no,
            program,
            amount,
            code,
            office,
            issued_by,
            issued_date,
            date_edited,    
            edited_by,
            reason_for_editing
        FROM issued_control_no
        ORDER BY issued_date DESC
    """).fetchall()
    conn.close()

    return render_template(
        'admin/edit_documents.html',
        documents=rows
    )

@app.route("/update-document", methods=["POST"])
def update_document():
    if "user" not in session:
        flash("You must be logged in.", "error")
        return redirect(url_for("login"))

    original_control_no = request.form.get("original_control_no", "").strip()

    control_no = request.form.get("control_no", "").strip()
    program = request.form.get("program", "").strip()
    amount = request.form.get("amount", "").strip()  # ✅ ADD THIS
    code = request.form.get("code", "").strip()
    office = request.form.get("office", "").strip()
    reason = request.form.get("reason_for_editing", "").strip()

    if not all([original_control_no, control_no, program, amount, code, office, reason]):
        flash("Please complete all fields (including Reason for Editing).", "error")
        return redirect(url_for("edit_documents"))

    edited_by = session.get("user", "Unknown")
    admin_office = session.get("office")
    date_edited = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = get_db_connection()

    # ✅ Get OLD values first (so we can log only what changed)
    old = conn.execute("""
        SELECT control_no, program, amount, code, office
        FROM issued_control_no
        WHERE control_no = ?
    """, (original_control_no,)).fetchone()

    if not old:
        conn.close()
        flash("Document not found.", "error")
        return redirect(url_for("edit_documents"))

    # ✅ Determine which fields changed (only include changed values)
    changed_parts = []

    if program != (old["program"] or ""):
        changed_parts.append(program)          # project title if changed
    if amount != (old["amount"] or ""):
        changed_parts.append(amount)           # amount if changed
    if code != (old["code"] or ""):
        changed_parts.append(code)             # code if changed

    # office: include if changed; if not changed, still include current office in final message
    final_office = office
    # If you want to only show office when changed, uncomment below:
    # if office != (old["office"] or ""):
    #     changed_parts.append(office)

    changed_text = " ".join(changed_parts).strip()

    # ✅ Update issued_control_no
    conn.execute("""
        UPDATE issued_control_no
        SET control_no = ?,
            program = ?,
            amount = ?,      -- ✅ ADD THIS
            code = ?,
            office = ?,
            date_edited = ?,
            edited_by = ?,
            reason_for_editing = ?
        WHERE control_no = ?
    """, (control_no, program, amount, code, office, date_edited, edited_by, reason, original_control_no))

    # ✅ AUDIT TRAIL ENTRY (matches your required format)
    # "(username) edited the document (project title) if title (Amount) if amount (Code) if code and (office) - (reason)"
    action_text = f"{edited_by} edited the document {changed_text} and {final_office} - {reason}"

    conn.execute("""
        INSERT INTO audit_trail (username, office, action, date_time)
        VALUES (?, ?, ?, ?)
    """, (edited_by, admin_office, action_text, date_edited))

    conn.commit()
    conn.close()

    flash("Document updated successfully.", "success")
    return redirect(url_for("edit_documents"))

@app.route("/delete-document/<control_no>", methods=["POST"])
def delete_document(control_no):
    # ✅ must be logged in
    if "user" not in session:
        return jsonify({"message": "Session expired. Please login again."}), 401

    # ✅ admin only
    if (session.get("role") or "").lower() != "admin":
        return jsonify({"message": "Access denied"}), 403

    username = session.get("user", "Unknown")
    admin_office = session.get("office")
    date_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = get_db_connection()
    cur = conn.cursor()

    # ✅ Get document details BEFORE deleting (for audit trail)
    cur.execute("""
        SELECT control_no, office
        FROM issued_control_no
        WHERE control_no = ?
    """, (control_no,))
    row = cur.fetchone()

    if not row:
        conn.close()
        return jsonify({"message": "Document not found"}), 404

    deleted_control_no = row["control_no"]
    deleted_office = row["office"]

    # ✅ Delete document
    cur.execute("DELETE FROM issued_control_no WHERE control_no = ?", (control_no,))

    # ✅ AUDIT TRAIL ENTRY
    action_text = f"{username} deleted the control number {deleted_control_no} - {deleted_office}"

    cur.execute("""
        INSERT INTO audit_trail (username, office, action, date_time)
        VALUES (?, ?, ?, ?)
    """, (
        username,
        admin_office,
        action_text,
        date_time
    ))

    conn.commit()
    conn.close()

    return jsonify({"message": "Document deleted successfully!"}), 200

@app.route("/tracking")
def tracking_page():
    return render_template("admin/tracking.html")



# =========================================================
# OME DASHBOARD
# =========================================================
@app.route("/ome/dashboard")
def ome_dashboard():
    if "user" not in session:
        flash("Please login first.", "error")
        return redirect(url_for("login"))

    if (session.get("office") or "").upper() != "OME":
        flash("Access denied.", "error")
        return redirect(url_for("dashboard"))

    conn = get_db_connection()

    # ✅ card count (NOT received yet)
    issued_count_ome = conn.execute("""
        SELECT COUNT(*) AS c
        FROM issued_control_no
        WHERE UPPER(TRIM(office)) = 'OME'
          AND received = 0
    """).fetchone()["c"]

    # ✅ ISSUED modal → ONLY NOT RECEIVED
    issued_rows_ome = conn.execute("""
        SELECT
            id,
            control_no,
            program,
            amount,
            source_of_fund,
            code,
            issued_date,
            received_date
        FROM issued_control_no
        WHERE UPPER(TRIM(office)) = 'OME'
          AND received = 0
        ORDER BY id DESC
    """).fetchall()

    # ✅ RECEIVED modal → ONLY RECEIVED
    received_rows_ome = conn.execute("""
        SELECT
            id,
            control_no,
            program,
            amount,
            source_of_fund,
            code,
            received_date
        FROM issued_control_no
        WHERE UPPER(TRIM(office)) = 'OME'
          AND received = 1
        ORDER BY received_date DESC
    """).fetchall()

    conn.close()

    return render_template(
        "ome/ome_dashboard.html",
        issued_count_ome=issued_count_ome,
        issued_rows_ome=issued_rows_ome,
        received_rows_ome=received_rows_ome,
        user=session.get("user"),
        role=session.get("role"),
        office=session.get("office"),
    )

# =========================================================
# API: RECEIVED CONTROL NOS (for Select Here dropdown) (OME)
# =========================================================
@app.route("/ome/api/received-control-nos", methods=["GET"])
def api_received_control_nos():
    if "user" not in session:
        return jsonify({"success": False, "message": "Please login first."}), 401

    user_office = (session.get("office") or "").strip().upper()
    if not user_office:
        return jsonify({"success": False, "message": "Missing office in session."}), 400

    conn = get_db_connection()

    rows = conn.execute("""
        SELECT
            id,
            control_no,
            program,
            amount,
            source_of_fund,   -- ✅ ADD THIS
            code
        FROM issued_control_no
        WHERE UPPER(TRIM(office)) = ?
          AND received = 1
        ORDER BY issued_date DESC, id DESC
    """, (user_office,)).fetchall()

    conn.close()

    options = []
    for r in rows:
        # ✅ keep amount raw; JS will format it (recommended)
        options.append({
            "id": r["id"],
            "code": r["code"],
            "control_no": r["control_no"],
            "program": r["program"],
            "amount": r["amount"],
            "source_of_fund": r["source_of_fund"],
        })

    return jsonify({"success": True, "options": options})


# =========================================================
# ✅ NEW API: TRANSMITTING DOCUMENTS (populate table)
# =========================================================
@app.route("/ome/api/transmitting-documents", methods=["GET"])
def ome_api_transmitting_documents():
    if "user" not in session:
        return jsonify(success=False, message="Please login first."), 401

    if (session.get("office") or "").upper() != "OME":
        return jsonify(success=False, message="Access denied."), 403

    conn = get_db_connection()
    try:
        # transmitting_documents doesn't store "program", so we LEFT JOIN issued_control_no
        rows = conn.execute("""
            SELECT
                td.id,
                td.control_no,
                td.code,
                COALESCE(ic.program, '') AS program,
                td.document_type,
                td.send_to,
                td.signatories,
                td.status,
                td.created_at
            FROM transmitting_documents td
            LEFT JOIN issued_control_no ic
              ON ic.control_no = td.control_no
             AND UPPER(TRIM(ic.code)) = UPPER(TRIM(td.code))
            ORDER BY td.created_at DESC, td.id DESC
        """).fetchall()

        data = []
        for r in rows:
            data.append({
                "id": r["id"],
                "control_no": r["control_no"],
                "code": r["code"],
                "program": r["program"],
                "document_type": r["document_type"],
                "send_to": r["send_to"],
                "signatories": r["signatories"],
                "status": r["status"],
                "created_at": r["created_at"],
            })

        return jsonify(success=True, rows=data)
    finally:
        conn.close()

# =========================================================
# RECEIVE CONTROL NO (OME)
# =========================================================
@app.route("/receive-control_no", methods=["POST"])
def receive_control_no():
    if "user" not in session:
        return jsonify({"success": False, "message": "Please login first."}), 401

    if (session.get("office") or "").upper() != "OME":
        return jsonify({"success": False, "message": "Access denied."}), 403

    doc_id = request.form.get("id")
    if not doc_id:
        return jsonify({"success": False, "message": "Missing document id."}), 400

    received_by = session.get("user", "Unknown")
    user_office = session.get("office", "Unknown")
    received_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = get_db_connection()

    # ✅ Get document details BEFORE updating (audit trail)
    doc = conn.execute("""
        SELECT id, control_no, program, issued_by
        FROM issued_control_no
        WHERE id = ?
    """, (doc_id,)).fetchone()

    if not doc:
        conn.close()
        return jsonify({"success": False, "message": "Document not found."}), 404

    # ✅ MARK AS RECEIVED (PROPER WAY)
    cur = conn.execute("""
        UPDATE issued_control_no
        SET
            received = 1,
            received_date = ?,
            received_by = ?
        WHERE id = ?
          AND received = 0
    """, (received_date, received_by, doc_id))
    conn.commit()

    # ✅ already received protection
    if cur.rowcount == 0:
        conn.close()
        return jsonify({"success": False, "message": "Already received or not found."}), 409

    # ✅ recompute NOT RECEIVED count
    new_count = conn.execute("""
        SELECT COUNT(*) AS c
        FROM issued_control_no
        WHERE UPPER(TRIM(office)) = 'OME'
          AND received = 0
    """).fetchone()["c"]

    # ✅ fetch received row (for modal auto-update)
    received_row = conn.execute("""
        SELECT
            id,
            control_no,
            program,
            amount,
            source_of_fund,
            code,
            received_date
        FROM issued_control_no
        WHERE id = ?
    """, (doc_id,)).fetchone()

    # ✅ AUDIT TRAIL
    action_text = (
        f"{received_by} of {user_office} Received the Control Number "
        f"{doc['control_no']} for {doc['program']} "
        f"Issued by {doc['issued_by']}"
    )

    conn.execute("""
        INSERT INTO audit_trail (username, office, action, date_time)
        VALUES (?, ?, ?, ?)
    """, (
        received_by,
        user_office,
        action_text,
        received_date
    ))

    conn.commit()
    conn.close()

    # ✅ AJAX response
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return jsonify({
            "success": True,
            "new_count": new_count,
            "received_row": dict(received_row) if received_row else None
        })

    flash("Document marked as received.", "success")
    return redirect(url_for("ome_dashboard"))

# =========================================================
# ADD DOCUMENT PAGE (OME)
# =========================================================
@app.route("/add_document_ome")
def add_document_ome():
    if "user" not in session:
        flash("Please login first.", "error")
        return redirect(url_for("login"))

    if (session.get("office") or "").upper() != "OME":
        flash("Access denied.", "error")
        return redirect(url_for("dashboard"))

    return render_template("ome/add_document_ome.html")

# =========================================================
# API: SIGNATORIES
# =========================================================
@app.route("/api/signatories")
def api_signatories():
    if "user" not in session:
        return jsonify(success=False, message="Unauthorized"), 401

    office = (request.args.get("office") or "").strip().upper()
    keywords_raw = (request.args.get("keywords") or "").strip()

    if not office:
        return jsonify(success=True, options=[])

    keywords = [k.strip() for k in keywords_raw.split("|") if k.strip()]
    if not keywords:
        keywords = [office]

    conn = get_db_connection()
    try:
        where = "UPPER(TRIM(office_department)) = ?"
        params = [office]

        for kw in keywords:
            where += " OR UPPER(TRIM(designation)) LIKE ?"
            params.append(f"%{kw.upper()}%")

        rows = conn.execute(f"""
            SELECT id, name, office_department, designation
            FROM signatories
            WHERE {where}
            ORDER BY name ASC
        """, params).fetchall()

        options = []
        for r in rows:
            options.append({
                "id": r["id"],
                "label": f"{r['name']} — {r['designation']}"
            })

        return jsonify(success=True, options=options)
    finally:
        conn.close()

# =========================================================
# ✅ ADD DOCUMENT (OME) -> SAVE TO transmitting_documents
# =========================================================
@app.route("/ome/add-document", methods=["POST"])
def ome_add_document():
    if "user" not in session:
        return jsonify(success=False, message="Please login first."), 401

    if (session.get("office") or "").upper() != "OME":
        return jsonify(success=False, message="Access denied."), 403

    issued_control_id = (request.form.get("issued_control_id") or "").strip()
    document_type = (request.form.get("document_type") or "").strip()
    send_to = (request.form.get("send_to") or "").strip()
    signatory_id = (request.form.get("signatory_id") or "").strip()
    status = (request.form.get("status") or "").strip()

    # ✅ validate required fields
    if not issued_control_id:
        return jsonify(success=False, message="Select here is required."), 400
    if not document_type:
        return jsonify(success=False, message="Document Type is required."), 400
    if not send_to:
        return jsonify(success=False, message="Send to is required."), 400
    if not signatory_id:
        return jsonify(success=False, message="Signatories is required."), 400
    if not status:
        return jsonify(success=False, message="Status is required."), 400

    # ✅ optional file upload
    file_path = None
    file = request.files.get("file")
    if file and file.filename:
        try:
            if "allowed_file" in globals() and not allowed_file(file.filename):
                return jsonify(success=False, message="Invalid file type."), 400
        except Exception:
            pass

        upload_dir = os.path.join("static", "uploads", "transmitting_documents")
        os.makedirs(upload_dir, exist_ok=True)

        safe_name = secure_filename(file.filename)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        final_name = f"{ts}__{safe_name}"
        save_path = os.path.join(upload_dir, final_name)
        file.save(save_path)

        file_path = save_path.replace("\\", "/")

    username = session.get("user", "Unknown")
    office = session.get("office", "Unknown")  # ✅ store sender office
    created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # ✅ NEW COLUMN VALUES
    send_by = username
    received = 0
    received_date = None
    received_by = None

    # ✅ helper: normalize amount safely (handles "1,200,000.00", "", None)
    def normalize_amount(val):
        if val is None:
            return 0.0
        s = str(val).strip()
        if not s:
            return 0.0
        s = s.replace(",", "")
        try:
            return float(s)
        except Exception:
            return 0.0

    conn = get_db_connection()
    try:
        # ✅ 1) Pull control_no + code + program(project_title) + source_of_fund + amount
        issued_row = conn.execute("""
            SELECT control_no, code, program, source_of_fund, amount
            FROM issued_control_no
            WHERE id = ?
        """, (issued_control_id,)).fetchone()

        if not issued_row:
            return jsonify(success=False, message="Selected control number not found."), 404

        control_no = issued_row["control_no"]
        code = issued_row["code"]
        project_title = issued_row["program"] or ""
        source_of_fund = issued_row["source_of_fund"] or ""

        # ✅ FIX: normalize amount even if stored as TEXT with commas
        amount = normalize_amount(issued_row["amount"])

        # ✅ 2) Pull signatory label
        sig_row = conn.execute("""
            SELECT name, designation
            FROM signatories
            WHERE id = ?
        """, (signatory_id,)).fetchone()

        if not sig_row:
            return jsonify(success=False, message="Selected signatory not found."), 404

        signatories_text = f"{sig_row['name']} — {sig_row['designation']}"

        # ✅ 3) INSERT — NOW INCLUDES project_title + source_of_fund + amount + office
        conn.execute("""
            INSERT INTO transmitting_documents (
                control_no,
                code,
                project_title,
                source_of_fund,
                amount,
                document_type,
                send_to,
                send_by,
                office,
                file_path,
                signatories,
                status,
                received,
                received_date,
                received_by,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            control_no,
            code,
            project_title,
            source_of_fund,
            amount,
            document_type,
            send_to,
            send_by,
            office,
            file_path,
            signatories_text,
            status,
            received,
            received_date,
            received_by,
            created_at
        ))

        # ✅ 4) audit trail
        action_text = (
            f"{username} transmitted {code}{control_no} "
            f"({document_type}) to {send_to}"
        )

        conn.execute("""
            INSERT INTO audit_trail (username, office, action, date_time)
            VALUES (?, ?, ?, ?)
        """, (username, office, action_text, created_at))

        conn.commit()

    except Exception as e:
        conn.rollback()
        current_app.logger.exception("Failed to insert transmitting_documents")
        return jsonify(success=False, message=f"Failed to save transmitting document: {e}"), 500
    finally:
        conn.close()

    return jsonify(success=True, message="Document sent and saved.", file_path=file_path)



# =========================================================
# ✅ MBO DASHBOARD (populate table from transmitting_documents)
# =========================================================
@app.route("/mbo/dashboard")
def mbo_dashboard():
    if "user" not in session:
        flash("Please login first.", "error")
        return redirect(url_for("login"))

    if (session.get("office") or "").upper() != "MBO":
        flash("Access denied.", "error")
        return redirect(url_for("dashboard"))

    conn = get_db_connection()

    # ✅ TABLE ROWS: ONLY show documents sent TO MBO that are NOT YET RECEIVED
    transmitted_rows_mbo = conn.execute("""
        SELECT
            td.id,
            td.control_no,
            COALESCE(icn.program, '-') AS program,   -- Program/Project Title
            td.document_type,
            td.code,
            td.send_by AS sender,
            td.received,
            td.received_date
        FROM transmitting_documents td
        LEFT JOIN issued_control_no icn
          ON icn.control_no = td.control_no
         AND icn.code = td.code
        WHERE UPPER(TRIM(td.send_to)) = 'MBO'
          AND (td.received IS NULL OR td.received = 0)
          AND td.received_date IS NULL
        ORDER BY td.id DESC
    """).fetchall()

    # ✅ CARDS
    total_docs_mbo = conn.execute("""
        SELECT COUNT(*) AS c
        FROM transmitting_documents
        WHERE UPPER(TRIM(send_to)) = 'MBO'
    """).fetchone()["c"]

    pending_count_mbo = conn.execute("""
        SELECT COUNT(*) AS c
        FROM transmitting_documents
        WHERE UPPER(TRIM(send_to)) = 'MBO'
          AND (received IS NULL OR received = 0)
          AND received_date IS NULL
    """).fetchone()["c"]

    received_count_mbo = conn.execute("""
        SELECT COUNT(*) AS c
        FROM transmitting_documents
        WHERE UPPER(TRIM(send_to)) = 'MBO'
          AND received = 1
    """).fetchone()["c"]

    # If you want, "To Received" can be same as pending
    to_receive_count_mbo = pending_count_mbo

    conn.close()

    return render_template(
        "mbo/mbo_dashboard.html",
        transmitted_rows_mbo=transmitted_rows_mbo,
        total_docs_mbo=total_docs_mbo,
        pending_count_mbo=pending_count_mbo,
        to_receive_count_mbo=to_receive_count_mbo,
        received_count_mbo=received_count_mbo,

        # keep your existing modal vars if you already have them:
        # issued_rows_mbo=issued_rows_mbo,
        # received_rows_mbo=received_rows_mbo,
        # issued_count_mbo=issued_count_mbo,
    )

# =========================================================
# API: RECEIVED CONTROL NOS (for Select Here dropdown) (MBO)
# =========================================================
@app.route("/mbo/api/received-control-nos", methods=["GET"])
def mbo_api_received_control_nos():
    if "user" not in session:
        return jsonify({"success": False, "message": "Please login first."}), 401

    user_office = (session.get("office") or "").strip().upper()
    if user_office != "MBO":
        return jsonify({"success": False, "message": "Access denied."}), 403

    conn = get_db_connection()

    rows = conn.execute("""
        SELECT
            id,
            control_no,
            program,
            amount,
            code
        FROM issued_control_no
        WHERE UPPER(TRIM(office)) = ?
          AND received = 1
        ORDER BY issued_date DESC, id DESC
    """, (user_office,)).fetchall()

    conn.close()

    options = []
    for r in rows:
        raw_amount = r["amount"]

        if raw_amount is None or str(raw_amount).strip() == "":
            amount_str = "0.00"
        else:
            cleaned = str(raw_amount).replace(",", "").strip()
            try:
                amount_val = float(cleaned)
                amount_str = f"{amount_val:,.2f}"
            except ValueError:
                amount_str = str(raw_amount)

        label = f"{r['code']}{r['control_no']}-{r['program']}, {amount_str}"

        options.append({
            "id": r["id"],
            "label": label
        })

    return jsonify({"success": True, "options": options})

# =========================================================
# ✅ API: TRANSMITTING DOCUMENTS (populate table) (MBO)
# =========================================================
@app.route("/mbo/api/transmitting-documents", methods=["GET"])
def mbo_api_transmitting_documents():
    if "user" not in session:
        return jsonify(success=False, message="Please login first."), 401

    if (session.get("office") or "").upper() != "MBO":
        return jsonify(success=False, message="Access denied."), 403

    conn = get_db_connection()
    try:
        rows = conn.execute("""
            SELECT
                td.id,
                td.control_no,
                td.code,
                COALESCE(ic.program, '') AS program,
                td.document_type,
                td.send_to,
                td.signatories,
                td.status,
                td.created_at
            FROM transmitting_documents td
            LEFT JOIN issued_control_no ic
              ON ic.control_no = td.control_no
             AND UPPER(TRIM(ic.code)) = UPPER(TRIM(td.code))
            ORDER BY td.created_at DESC, td.id DESC
        """).fetchall()

        data = []
        for r in rows:
            data.append({
                "id": r["id"],
                "control_no": r["control_no"],
                "code": r["code"],
                "program": r["program"],
                "document_type": r["document_type"],
                "send_to": r["send_to"],
                "signatories": r["signatories"],
                "status": r["status"],
                "created_at": r["created_at"],
            })

        return jsonify(success=True, rows=data)
    finally:
        conn.close()

# =========================================================
# RECEIVE CONTROL NO (MBO)
# =========================================================
@app.route("/mbo/receive-control_no", methods=["POST"])
def mbo_receive_control_no():
    if "user" not in session:
        return jsonify({"success": False, "message": "Please login first."}), 401

    if (session.get("office") or "").upper() != "MBO":
        return jsonify({"success": False, "message": "Access denied."}), 403

    doc_id = request.form.get("id")
    if not doc_id:
        return jsonify({"success": False, "message": "Missing document id."}), 400

    received_by = session.get("user", "Unknown")
    user_office = session.get("office", "Unknown")
    received_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = get_db_connection()

    doc = conn.execute("""
        SELECT id, control_no, program, issued_by
        FROM issued_control_no
        WHERE id = ?
    """, (doc_id,)).fetchone()

    if not doc:
        conn.close()
        return jsonify({"success": False, "message": "Document not found."}), 404

    cur = conn.execute("""
        UPDATE issued_control_no
        SET
            received = 1,
            received_date = ?,
            received_by = ?
        WHERE id = ?
          AND received = 0
    """, (received_date, received_by, doc_id))
    conn.commit()

    if cur.rowcount == 0:
        conn.close()
        return jsonify({"success": False, "message": "Already received or not found."}), 409

    new_count = conn.execute("""
        SELECT COUNT(*) AS c
        FROM issued_control_no
        WHERE UPPER(TRIM(office)) = 'MBO'
          AND received = 0
    """).fetchone()["c"]

    received_row = conn.execute("""
        SELECT
            id,
            control_no,
            program,
            amount,
            source_of_fund,
            code,
            received_date
        FROM issued_control_no
        WHERE id = ?
    """, (doc_id,)).fetchone()

    action_text = (
        f"{received_by} of {user_office} Received the Control Number "
        f"{doc['control_no']} for {doc['program']} "
        f"Issued by {doc['issued_by']}"
    )

    conn.execute("""
        INSERT INTO audit_trail (username, office, action, date_time)
        VALUES (?, ?, ?, ?)
    """, (
        received_by,
        user_office,
        action_text,
        received_date
    ))

    conn.commit()
    conn.close()

    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return jsonify({
            "success": True,
            "new_count": new_count,
            "received_row": dict(received_row) if received_row else None
        })

    flash("Document marked as received.", "success")
    return redirect(url_for("mbo_dashboard"))

# =========================================================
# ✅ MBO RECEIVE TRANSMITTED DOCUMENT
# =========================================================
@app.route("/mbo/receive-transmitted", methods=["POST"])
def mbo_receive_transmitted():
    if "user" not in session:
        return jsonify(success=False, message="Please login first."), 401

    if (session.get("office") or "").upper() != "MBO":
        return jsonify(success=False, message="Access denied."), 403

    doc_id = (request.form.get("id") or "").strip()
    if not doc_id.isdigit():
        return jsonify(success=False, message="Invalid document id."), 400

    username = session.get("user", "Unknown")
    office = session.get("office", "Unknown")
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = get_db_connection()
    try:
        # ✅ Make sure the record exists AND is intended for MBO
        row = conn.execute("""
            SELECT id, control_no, code, document_type, send_to, received, received_date
            FROM transmitting_documents
            WHERE id = ?
        """, (doc_id,)).fetchone()

        if not row:
            return jsonify(success=False, message="Record not found."), 404

        if (row["send_to"] or "").strip().upper() != "MBO":
            return jsonify(success=False, message="This document is not for MBO."), 403

        # ✅ Prevent double receive (handles received=1 OR received_date already set)
        if row["received"] == 1 or row["received_date"] is not None:
            return jsonify(success=False, message="This document is already received."), 400

        # ✅ Update receiving fields
        conn.execute("""
            UPDATE transmitting_documents
            SET received = 1,
                received_date = ?,
                received_by = ?
            WHERE id = ?
        """, (now, username, doc_id))

        # ✅ Audit trail (recommended)
        action_text = f"{username} received transmitted document {row['code']}{row['control_no']} ({row['document_type']})"
        conn.execute("""
            INSERT INTO audit_trail (username, office, action, date_time)
            VALUES (?, ?, ?, ?)
        """, (username, office, action_text, now))

        conn.commit()

        return jsonify(success=True, message="Document marked as received.")

    except Exception as e:
        conn.rollback()
        current_app.logger.exception("Failed to receive transmitted document")
        return jsonify(success=False, message=f"Failed to receive: {e}"), 500
    finally:
        conn.close()

# =========================================================
# ADD DOCUMENT PAGE (MBO)
# =========================================================
@app.route("/add_document_mbo")
def add_document_mbo():
    if "user" not in session:
        flash("Please login first.", "error")
        return redirect(url_for("login"))

    if (session.get("office") or "").upper() != "MBO":
        flash("Access denied.", "error")
        return redirect(url_for("dashboard"))

    # create this file if you want a dedicated add doc page:
    # templates/add_document_mbo.html
    return render_template("add_document_mbo.html")

# =========================================================
# ✅ ADD DOCUMENT (MBO) -> SAVE TO transmitting_documents
# =========================================================
@app.route("/mbo/add-document", methods=["POST"])
def mbo_add_document():
    if "user" not in session:
        return jsonify(success=False, message="Please login first."), 401

    if (session.get("office") or "").upper() != "MBO":
        return jsonify(success=False, message="Access denied."), 403

    issued_control_id = (request.form.get("issued_control_id") or "").strip()
    document_type = (request.form.get("document_type") or "").strip()
    send_to = (request.form.get("send_to") or "").strip()
    signatory_id = (request.form.get("signatory_id") or "").strip()
    status = (request.form.get("status") or "").strip()

    if not issued_control_id:
        return jsonify(success=False, message="Select here is required."), 400
    if not document_type:
        return jsonify(success=False, message="Document Type is required."), 400
    if not send_to:
        return jsonify(success=False, message="Send to is required."), 400
    if not signatory_id:
        return jsonify(success=False, message="Signatories is required."), 400
    if not status:
        return jsonify(success=False, message="Status is required."), 400

    file_path = None
    file = request.files.get("file")
    if file and file.filename:
        try:
            if "allowed_file" in globals() and not allowed_file(file.filename):
                return jsonify(success=False, message="Invalid file type."), 400
        except Exception:
            pass

        upload_dir = os.path.join("static", "uploads", "transmitting_documents")
        os.makedirs(upload_dir, exist_ok=True)

        safe_name = secure_filename(file.filename)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        final_name = f"{ts}__{safe_name}"
        save_path = os.path.join(upload_dir, final_name)
        file.save(save_path)

        file_path = save_path.replace("\\", "/")

    username = session.get("user", "Unknown")
    office = session.get("office", "Unknown")
    created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = get_db_connection()
    try:
        issued_row = conn.execute("""
            SELECT control_no, code, program
            FROM issued_control_no
            WHERE id = ?
        """, (issued_control_id,)).fetchone()

        if not issued_row:
            return jsonify(success=False, message="Selected control number not found."), 404

        control_no = issued_row["control_no"]
        code = issued_row["code"]

        sig_row = conn.execute("""
            SELECT name, designation
            FROM signatories
            WHERE id = ?
        """, (signatory_id,)).fetchone()

        if not sig_row:
            return jsonify(success=False, message="Selected signatory not found."), 404

        signatories_text = f"{sig_row['name']} — {sig_row['designation']}"

        conn.execute("""
            INSERT INTO transmitting_documents
            (control_no, code, document_type, send_to, file_path, signatories, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            control_no,
            code,
            document_type,
            send_to,
            file_path,
            signatories_text,
            status,
            created_at
        ))

        action_text = f"{username} transmitted {code}{control_no} ({document_type}) to {send_to} - {status}"
        conn.execute("""
            INSERT INTO audit_trail (username, office, action, date_time)
            VALUES (?, ?, ?, ?)
        """, (username, office, action_text, created_at))

        conn.commit()

    except Exception as e:
        conn.rollback()
        current_app.logger.exception("Failed to insert transmitting_documents (MBO)")
        return jsonify(success=False, message=f"Failed to save transmitting document: {e}"), 500
    finally:
        conn.close()

    return jsonify(success=True, message="Document sent and saved.", file_path=file_path)

@app.route("/mbo/select-action")
def select_action_mbo():
    if "user" not in session:
        flash("Please login first.", "error")
        return redirect(url_for("login"))

    if (session.get("office") or "").upper() != "MBO":
        flash("Access denied.", "error")
        return redirect(url_for("dashboard"))

    conn = get_db_connection()

    # ✅ COUNT: Received + sent to MBO + status = for_obligation
    obligation_count = conn.execute("""
        SELECT COUNT(*) AS c
        FROM transmitting_documents
        WHERE UPPER(TRIM(send_to)) = 'MBO'
          AND received = 1
          AND status = 'for_obligation'
    """).fetchone()["c"]

    # ✅ COUNT: Received + sent to MBO + status = for_signature
    signature_count = conn.execute("""
        SELECT COUNT(*) AS c
        FROM transmitting_documents
        WHERE UPPER(TRIM(send_to)) = 'MBO'
          AND received = 1
          AND status = 'for_signature'
    """).fetchone()["c"]

    conn.close()

    return render_template(
        "mbo/select_action_mbo.html",
        obligation_count=obligation_count,
        signature_count=signature_count
    )
# =========================================================
# ✅ OBLIGATE DOCUMENT (MBO) -> SAVE TO transmitting_documents
# =========================================================
from flask import render_template, request, session, flash, redirect, url_for

@app.route("/mbo/for-obligation")
def mbo_for_obligation():
    if "user" not in session:
        flash("Please login first.", "error")
        return redirect(url_for("login"))

    if (session.get("office") or "").upper() != "MBO":
        flash("Access denied.", "error")
        return redirect(url_for("dashboard"))

    office = (session.get("office") or "").strip().upper()
    search_query = (request.args.get("q") or "").strip()

    conn = get_db_connection()

    # =========================
    # MAIN TABLE (for obligation)
    # =========================
    sql = """
        SELECT
            id,
            control_no,
            code,
            document_type,
            project_title,
            amount,
            source_of_fund
        FROM transmitting_documents
        WHERE UPPER(TRIM(send_to)) = ?
          AND received = 1
          AND status = 'for_obligation'
    """
    params = [office]

    if search_query:
        sql += " AND control_no LIKE ? "
        params.append(f"%{search_query}%")

    sql += " ORDER BY id DESC "

    rows = conn.execute(sql, params).fetchall()

    formatted_rows = []
    for r in rows:
        r = dict(r)
        try:
            r["amount_fmt"] = f"{float(r.get('amount', 0) or 0):,.2f}"
        except Exception:
            r["amount_fmt"] = "0.00"
        formatted_rows.append(r)

    # =========================
    # RETURNED MODAL (obligation returns)
    # =========================
    returned_rows = conn.execute("""
        SELECT
            id,
            control_no,
            code,
            document_type,
            program,
            amount,
            source_of_fund,
            status,
            returned_date,
            returned_reason
        FROM returned_documents_obligation
        WHERE UPPER(TRIM(office)) = 'MBO'
        ORDER BY id DESC
    """).fetchall()

    formatted_returned_rows = []
    for r in returned_rows:
        r = dict(r)
        try:
            r["amount_fmt"] = f"{float(r.get('amount', 0) or 0):,.2f}"
        except Exception:
            r["amount_fmt"] = "0.00"
        formatted_returned_rows.append(r)

    # =========================
    # OBLIGATED MODAL (obligated_documents)
    # =========================
    obligated_rows = conn.execute("""
        SELECT
            id,
            control_no,
            code,
            document_type,
            program,
            amount,
            source_of_fund,
            status,
            obr_no,
            obligated_date
        FROM obligated_documents
        WHERE UPPER(TRIM(obligated_office)) = 'MBO'
        ORDER BY id DESC
    """).fetchall()

    formatted_obligated_rows = []
    for o in obligated_rows:
        o = dict(o)
        try:
            o["amount_fmt"] = f"{float(o.get('amount', 0) or 0):,.2f}"
        except Exception:
            o["amount_fmt"] = "0.00"
        formatted_obligated_rows.append(o)

    conn.close()

    return render_template(
        "mbo/for_obligation.html",
        rows=formatted_rows,
        returned_rows=formatted_returned_rows,
        obligated_rows=formatted_obligated_rows,   # ✅ NEW
        search_query=search_query
    )

@app.route("/mbo/obligate-document", methods=["POST"])
def mbo_obligate_document():
    # ✅ auth
    if "user" not in session:
        return jsonify(success=False, message="Please login first."), 401

    if (session.get("office") or "").upper() != "MBO":
        return jsonify(success=False, message="Access denied."), 403

    doc_id = (request.form.get("doc_id") or request.form.get("id") or "").strip()
    obr_no = (request.form.get("obligation_request_no") or "").strip()
    status = (request.form.get("status") or "").strip()

    if not doc_id or not doc_id.isdigit():
        return jsonify(success=False, message="Missing/Invalid document id."), 400
    if not obr_no:
        return jsonify(success=False, message="Obligation Request No. is required."), 400
    if not status or status == "select_here":
        return jsonify(success=False, message="Please select a valid status."), 400

    username = (session.get("user") or "Unknown").strip()
    office = (session.get("office") or "Unknown").strip().upper()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = get_db_connection()
    try:
        # ✅ ensure doc exists and belongs to MBO inbox (send_to = MBO)
        row = conn.execute("""
            SELECT
                id,
                control_no,
                code,
                document_type,
                project_title,
                amount,
                source_of_fund,
                received
            FROM transmitting_documents
            WHERE id = ?
              AND UPPER(TRIM(send_to)) = 'MBO'
        """, (int(doc_id),)).fetchone()

        if not row:
            return jsonify(success=False, message="Document not found."), 404

        if int(row["received"] or 0) != 1:
            return jsonify(success=False, message="Document must be marked as received first."), 409

        # =========================================================
        # ✅ 1) Update transmitting_documents (keep your existing behavior)
        # =========================================================
        conn.execute("""
            UPDATE transmitting_documents
            SET
                obr_no = ?,
                status = ?
            WHERE id = ?
        """, (obr_no, status, int(doc_id)))

        # =========================================================
        # ✅ 2) Insert into obligated_documents (NEW)
        #    - prevent duplicates using a quick check
        # =========================================================
        exists = conn.execute("""
            SELECT 1
            FROM obligated_documents
            WHERE control_no = ?
              AND code = ?
              AND obr_no = ?
            LIMIT 1
        """, (row["control_no"], row["code"], obr_no)).fetchone()

        if not exists:
            conn.execute("""
                INSERT INTO obligated_documents (
                    transmitting_id,
                    control_no,
                    code,
                    document_type,
                    program,
                    amount,
                    source_of_fund,
                    obr_no,
                    status,
                    obligated_by,
                    obligated_office,
                    obligated_date
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                row["id"],
                row["control_no"],
                row["code"],
                row["document_type"],
                row["project_title"],
                row["amount"],
                row["source_of_fund"],
                obr_no,
                status,
                username,
                office,
                now
            ))

        # =========================================================
        # ✅ 3) audit trail
        # =========================================================
        action_text = (
            f"{username} obligated {row['code']}{row['control_no']} "
            f"with OBR No. {obr_no} and set status to {status}"
        )

        conn.execute("""
            INSERT INTO audit_trail (username, office, action, date_time)
            VALUES (?, ?, ?, ?)
        """, (username, office, action_text, now))

        conn.commit()
        return jsonify(success=True, message="Document obligated successfully.")

    except Exception as e:
        conn.rollback()
        current_app.logger.exception("Failed to obligate document")
        return jsonify(success=False, message=f"Failed to obligate: {e}"), 500
    finally:
        conn.close()

@app.route("/mbo/return-signature-document", methods=["POST"])
def mbo_return_document():
    if "user" not in session:
        return jsonify(success=False, message="Please login first."), 401

    if (session.get("office") or "").upper() != "MBO":
        return jsonify(success=False, message="Access denied."), 403

    doc_id = (request.form.get("doc_id") or "").strip()
    returned_reason = (request.form.get("returned_reason") or "").strip()
    status = (request.form.get("status") or "").strip()

    if not doc_id.isdigit():
        return jsonify(success=False, message="Invalid document id."), 400
    if not returned_reason:
        return jsonify(success=False, message="Return reason is required."), 400
    if not status or status == "select_here":
        return jsonify(success=False, message="Please select a valid status."), 400

    returned_by = (session.get("user") or "").strip()
    returned_office = (session.get("office") or "").strip().upper()   # ✅ NEW (office of the user who returned)
    returned_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = get_db_connection()
    try:
        # ✅ Fetch sender office from transmitting_documents
        row = conn.execute("""
            SELECT
                id,
                control_no,
                code,
                document_type,
                project_title,
                amount,
                source_of_fund,
                office
            FROM transmitting_documents
            WHERE id = ?
        """, (int(doc_id),)).fetchone()

        if row is None:
            return jsonify(success=False, message="Document not found."), 404

        # ✅ returned_to now equals sender's office (e.g., OME)
        returned_to = (row["office"] or "").strip()
        program = (row["project_title"] or "").strip()

        # ✅ INSERT INCLUDING office column
        conn.execute("""
            INSERT INTO returned_documents (
                control_no,
                code,
                document_type,
                program,
                amount,
                source_of_fund,
                returned_by,
                office,              -- ✅ NEW COLUMN
                returned_to,
                returned_date,
                received,
                received_date,
                received_by,
                returned_reason,
                status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, NULL, NULL, ?, ?)
        """, (
            row["control_no"],
            row["code"],
            row["document_type"],
            program,
            row["amount"],
            row["source_of_fund"],
            returned_by,
            returned_office,       # ✅ VALUE FOR office (who performed the return)
            returned_to,
            returned_date,
            returned_reason,
            status
        ))

        conn.execute("DELETE FROM transmitting_documents WHERE id = ?", (int(doc_id),))

        conn.commit()
        return jsonify(success=True, message="Document returned successfully.")

    except Exception as e:
        conn.rollback()
        return jsonify(success=False, message=f"Error: {str(e)}"), 500
    finally:
        conn.close()

@app.route("/mbo/return-obligation-document", methods=["POST"])
def mbo_return_obligation_document():
    if "user" not in session:
        return jsonify(success=False, message="Please login first."), 401

    if (session.get("office") or "").upper() != "MBO":
        return jsonify(success=False, message="Access denied."), 403

    doc_id = (request.form.get("doc_id") or "").strip()
    returned_reason = (request.form.get("returned_reason") or "").strip()
    status = (request.form.get("status") or "").strip()

    if not doc_id.isdigit():
        return jsonify(success=False, message="Invalid document id."), 400
    if not returned_reason:
        return jsonify(success=False, message="Return reason is required."), 400
    if not status or status == "select_here":
        return jsonify(success=False, message="Please select a valid status."), 400

    returned_by = (session.get("user") or "").strip()
    returned_office = (session.get("office") or "").strip().upper()  # MBO
    returned_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = get_db_connection()
    try:
        # ✅ IMPORTANT: only pick docs that are really for obligation
        row = conn.execute("""
            SELECT
                id,
                control_no,
                code,
                document_type,
                project_title,
                amount,
                source_of_fund,
                office,
                status,
                received
            FROM transmitting_documents
            WHERE id = ?
              AND status = 'for_obligation'
              AND UPPER(TRIM(send_to)) = 'MBO'
              AND received = 1
        """, (int(doc_id),)).fetchone()

        if row is None:
            return jsonify(
                success=False,
                message="Document not found or not eligible for obligation return."
            ), 404

        returned_to = (row["office"] or "").strip()  # sender office (ex: OME)
        program = (row["project_title"] or "").strip()

        # ✅ Insert into obligation-only returned table
        conn.execute("""
            INSERT INTO returned_documents_obligation (
                control_no,
                code,
                document_type,
                program,
                amount,
                source_of_fund,
                returned_by,
                office,
                returned_to,
                returned_date,
                received,
                received_date,
                received_by,
                returned_reason,
                status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, NULL, NULL, ?, ?)
        """, (
            row["control_no"],
            row["code"],
            row["document_type"],
            program,
            row["amount"],
            row["source_of_fund"],
            returned_by,
            returned_office,   # MBO
            returned_to,       # sender office
            returned_date,
            returned_reason,
            status
        ))

        # ✅ remove original record so it disappears from obligation table
        conn.execute("DELETE FROM transmitting_documents WHERE id = ?", (int(doc_id),))

        conn.commit()
        return jsonify(success=True, message="Obligation document returned successfully.")

    except Exception as e:
        conn.rollback()
        return jsonify(success=False, message=f"Error: {str(e)}"), 500
    finally:
        conn.close()


# =========================================================
# ✅ FOR SIGNATURE PAGE (MBO) - includes file_path + search
# =========================================================
@app.route("/mbo/for-signature")
def mbo_for_signature():
    if "user" not in session:
        flash("Please login first.", "error")
        return redirect(url_for("login"))

    if (session.get("office") or "").upper() != "MBO":
        flash("Access denied.", "error")
        return redirect(url_for("dashboard"))

    office = (session.get("office") or "").strip().upper()
    q = (request.args.get("q") or "").strip()

    conn = get_db_connection()

    # ✅ For signature inbox
    rows = conn.execute("""
        SELECT id, control_no, code, document_type, project_title, amount, source_of_fund
        FROM transmitting_documents
        WHERE UPPER(TRIM(send_to)) = ?
          AND received = 1
          AND status = 'for_signature'
          AND (? = '' OR control_no LIKE ?)
        ORDER BY id DESC
    """, (office, q, f"%{q}%")).fetchall()

    # ✅ Returned documents list (MBO)
    returned_rows = conn.execute("""
        SELECT
            id,
            control_no,
            code,
            program,
            document_type,
            amount,
            source_of_fund,
            status,
            returned_date,
            returned_reason,
            office
        FROM returned_documents
        WHERE UPPER(TRIM(office)) = ?
        ORDER BY id DESC
    """, (office,)).fetchall()

    # ✅ Signed documents list (SIGNED BY THIS OFFICE)
    # NOTE:
    # - office        = origin office of the document (ex: OME)
    # - action_office = office who performed the signing (ex: MBO)
    signed_rows = conn.execute("""
        SELECT
            id,
            control_no,
            code,
            program,
            document_type,
            amount,
            source_of_fund,
            status,
            signed_date,
            office,
            action_office
        FROM signed_documents
        WHERE UPPER(TRIM(action_office)) = ?
        ORDER BY id DESC
    """, (office,)).fetchall()

    conn.close()

    return render_template(
        "mbo/for_signature.html",
        rows=rows,
        returned_rows=returned_rows,
        signed_rows=signed_rows,
        search_query=q
    )

# =========================================================
# ✅ SAFE PATH HELPER (prevents path traversal)
# =========================================================
def _safe_doc_abspath(file_path: str) -> str:
    """
    file_path stored like: 'static/uploads/transmitting_documents/20260212_xxx.pdf'
    """
    if not file_path:
        return ""

    rel = file_path.replace("\\", "/").lstrip("/")  # normalize
    abs_path = os.path.abspath(os.path.join(current_app.root_path, rel))

    allowed_root = os.path.abspath(
        os.path.join(current_app.root_path, "static", "uploads", "transmitting_documents")
    )

    # ✅ prevent path traversal
    if not abs_path.startswith(allowed_root + os.sep) and abs_path != allowed_root:
        return ""

    return abs_path

# =========================================================
# ✅ VIEW DOCUMENT (MBO) - inline open PDF
# =========================================================
@app.route("/mbo/view-document/<int:doc_id>")
def mbo_view_document(doc_id):
    if "user" not in session:
        abort(401)

    if (session.get("office") or "").upper() != "MBO":
        abort(403)

    office = (session.get("office") or "").strip().upper()

    conn = get_db_connection()
    row = conn.execute("""
        SELECT file_path
        FROM transmitting_documents
        WHERE id = ?
          AND UPPER(TRIM(send_to)) = ?
          AND received = 1
    """, (doc_id, office)).fetchone()
    conn.close()

    if not row:
        abort(404)

    abs_path = _safe_doc_abspath(row["file_path"] or "")
    if not abs_path or not os.path.exists(abs_path):
        abort(404)

    # ✅ open in browser (inline)
    return send_file(abs_path, as_attachment=False)

# =========================================================
# ✅ DOWNLOAD DOCUMENT (MBO) - force download
# =========================================================
@app.route("/mbo/download-document/<int:doc_id>")
def mbo_download_document(doc_id):
    if "user" not in session:
        abort(401)

    if (session.get("office") or "").upper() != "MBO":
        abort(403)

    office = (session.get("office") or "").strip().upper()

    conn = get_db_connection()
    row = conn.execute("""
        SELECT file_path, control_no, code, document_type
        FROM transmitting_documents
        WHERE id = ?
          AND UPPER(TRIM(send_to)) = ?
          AND received = 1
    """, (doc_id, office)).fetchone()
    conn.close()

    if not row:
        abort(404)

    abs_path = _safe_doc_abspath(row["file_path"] or "")
    if not abs_path or not os.path.exists(abs_path):
        abort(404)

    # nice filename (optional)
    safe_name = f"{row['code']}{row['control_no']}_{row['document_type']}.pdf".replace(" ", "_")
    safe_name = secure_filename(safe_name) or "document.pdf"

    return send_file(
        abs_path,
        as_attachment=True,
        download_name=safe_name
    )

# =========================================================
# ✅ SAVE DOCUMENT (MBO) - save the backup softcopy sent by the endusers
# =========================================================
@app.route("/mbo/save-document/<int:doc_id>", methods=["POST"])
def mbo_save_document(doc_id):
    if "user" not in session:
        return jsonify(success=False, message="Unauthorized"), 401

    if (session.get("office") or "").upper() != "MBO":
        return jsonify(success=False, message="Access denied"), 403

    office = (session.get("office") or "").strip().upper()
    saved_by = session.get("user")
    saved_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = get_db_connection()

    try:
        # ✅ Get document from transmitting_documents
        row = conn.execute("""
            SELECT
                control_no,
                code,
                document_type,
                project_title,
                amount,
                file_path,
                office
            FROM transmitting_documents
            WHERE id = ?
              AND UPPER(TRIM(send_to)) = ?
              AND received = 1
        """, (doc_id, office)).fetchone()

        if not row:
            return jsonify(success=False, message="Document not found"), 404

        # ✅ CHECK IF ALREADY SAVED
        existing = conn.execute("""
            SELECT id
            FROM saved_documents_backup
            WHERE control_no = ?
              AND code = ?
              AND document_type = ?
        """, (
            row["control_no"],
            row["code"],
            row["document_type"]
        )).fetchone()

        if existing:
            return jsonify(
                success=False,
                message="Document Already Saved to Backup"
            ), 400

        # ✅ Insert into saved_documents_backup
        conn.execute("""
            INSERT INTO saved_documents_backup (
                control_no,
                code,
                document_type,
                program,
                amount,
                file_path,
                office,
                saved_date,
                saved_by
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            row["control_no"],
            row["code"],
            row["document_type"],
            row["project_title"],
            row["amount"],
            row["file_path"],
            row["office"],
            saved_date,
            saved_by
        ))

        conn.commit()

        return jsonify(success=True, message="Document saved to backup successfully.")

    except Exception as e:
        conn.rollback()
        return jsonify(success=False, message=str(e)), 500

    finally:
        conn.close()

@app.route("/mbo/sign-document", methods=["POST"])
def mbo_sign_document():
    if "user" not in session:
        return jsonify(success=False, message="Unauthorized"), 401

    if (session.get("office") or "").upper() != "MBO":
        return jsonify(success=False, message="Access denied"), 403

    action_office = (session.get("office") or "").strip().upper()   # ✅ office of signer (MBO)
    signed_by = session.get("user", "Unknown")
    signed_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    doc_id = (request.form.get("doc_id") or "").strip()
    remarks = (request.form.get("remarks") or "").strip()
    status  = (request.form.get("status") or "").strip()

    if not doc_id.isdigit():
        return jsonify(success=False, message="Invalid document ID."), 400

    if not status or status == "select_here":
        return jsonify(success=False, message="Please select a valid status."), 400

    conn = get_db_connection()

    try:
        # ✅ Get document from transmitting_documents (must be in MBO inbox)
        row = conn.execute("""
            SELECT
                control_no,
                code,
                document_type,
                project_title,
                amount,
                source_of_fund,
                file_path,
                office
            FROM transmitting_documents
            WHERE id = ?
              AND UPPER(TRIM(send_to)) = ?
              AND received = 1
              AND status = 'for_signature'
        """, (int(doc_id), action_office)).fetchone()

        if not row:
            return jsonify(success=False, message="Document not found or not eligible for signing."), 404

        # ✅ Document's original office (where it came from)
        row_office = (row["office"] or "").strip() or action_office

        # ✅ Insert into signed_documents (NOW includes action_office)
        try:
            conn.execute("""
                INSERT INTO signed_documents (
                    control_no,
                    code,
                    document_type,
                    program,
                    amount,
                    source_of_fund,
                    file_path,
                    office,          -- ✅ document origin office
                    action_office,   -- ✅ signer office
                    signed_date,
                    signed_by,
                    remarks,
                    status
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                row["control_no"],
                row["code"],
                row["document_type"],
                row["project_title"],
                row["amount"],
                row["source_of_fund"],
                row["file_path"],
                row_office,
                action_office,
                signed_date,
                signed_by,
                remarks,
                status
            ))
        except sqlite3.IntegrityError:
            return jsonify(success=False, message="Document already signed."), 409

        # ✅ Remove from transmitting_documents AFTER successful insert
        conn.execute("""
            DELETE FROM transmitting_documents
            WHERE id = ?
              AND UPPER(TRIM(send_to)) = ?
              AND received = 1
              AND status = 'for_signature'
        """, (int(doc_id), action_office))

        # ✅ AUDIT TRAIL (format exactly as requested)
        doc_type = (row["document_type"] or "").strip()
        display_remarks = remarks.strip() if remarks.strip() else "none"

        action_text = (
            f"{signed_by} signed {row['control_no']} "
            f"{doc_type} and set status to {status} "
            f"with remarks: {display_remarks}"
        )

        conn.execute("""
            INSERT INTO audit_trail (username, office, action, date_time)
            VALUES (?, ?, ?, ?)
        """, (signed_by, action_office, action_text, signed_date))

        conn.commit()
        return jsonify(success=True, message="Document signed successfully and moved to signed records.")

    except Exception as e:
        conn.rollback()
        current_app.logger.exception("Failed to sign document")
        return jsonify(success=False, message=f"Failed to sign: {e}"), 500

    finally:
        conn.close()






# =========================
# RUN APP
# =========================

if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)

