import os
import uuid
import calendar
from pymysql.err import IntegrityError
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import date
from functools import wraps

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, send_from_directory, abort, flash
)

from werkzeug.utils import secure_filename
from database import get_db_connection, init_db


app = Flask(__name__)
app.secret_key = "freshmeet_admin_secret_key"

app.config["UPLOAD_FOLDER"] = os.path.join(app.root_path, "uploads")
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024

os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

ALLOWED_EXTENSIONS = {"pdf", "png", "jpg", "jpeg"}


# --------------------------------------------------
# DATABASE HELPERS
# --------------------------------------------------

def get_columns(conn, table):
    result = conn.execute(
        f"PRAGMA table_info({table})"
    ).fetchall()
    return [row["name"] for row in result]


def table_exists(conn, table):
    result = conn.execute(
        """
        SELECT name FROM sqlite_master
        WHERE type='table' AND name=?
        """,
        (table,)
    ).fetchone()
    return result is not None


def get_count(conn, table, condition=None):
    if not table_exists(conn, table):
        return 0

    query = f"SELECT COUNT(*) FROM {table}"

    if condition:
        query += f" WHERE {condition}"

    return conn.execute(query).fetchone()[0]


# --------------------------------------------------
# ADMIN LOGIN REQUIRED
# --------------------------------------------------

def admin_required(route):
    @wraps(route)
    def decorated(*args, **kwargs):
        if "admin_id" not in session:
            return redirect(url_for("login"))
        return route(*args, **kwargs)
    return decorated


# --------------------------------------------------
# FILE HELPERS
# --------------------------------------------------

def allowed_file(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
    )


def save_uploaded_file(file):
    if not file or not file.filename:
        return None

    if not allowed_file(file.filename):
        raise ValueError(
            "Only PDF, PNG, JPG and JPEG files are allowed."
        )

    original = secure_filename(file.filename)
    extension = original.rsplit(".", 1)[1].lower()
    filename = f"{uuid.uuid4().hex}.{extension}"

    file.save(
        os.path.join(app.config["UPLOAD_FOLDER"], filename)
    )

    return filename



def get_document_fields(module):
    if module == "sellers":
        return {
            "aadhaar_file": "Aadhaar Document",
            "pan_file": "PAN Document",
            "fssai_file": "FSSAI Document"
        }

    return {
        "rider_photo": "Rider Photo",
        "license_front": "Driving License (Front)",
        "license_back": "Driving License (Back)",
        "rc_front": "Vehicle RC (Front)",
        "rc_back": "Vehicle RC (Back)",
        "vehicle_photo": "Vehicle Photo"
    }


# --------------------------------------------------
# ADD MONTHS
# --------------------------------------------------

def add_months(original_date, months):
    month = original_date.month - 1 + months
    year = original_date.year + month // 12
    month = month % 12 + 1

    day = min(
        original_date.day,
        calendar.monthrange(year, month)[1]
    )

    return date(year, month, day)


# --------------------------------------------------
# OTHER MODULES CONFIGURATION

# --------------------------------------------------

MODULES = {
    "customers": {
        "title": "Customers",
        "table": "users",
        "columns": ["id", "name", "email", "mobile"],
        "actions": []
    },

    "products": {
        "title": "Products",
        "table": "products",
        "columns": ["id", "name", "category", "price", "status"],
        "actions": ["Active", "Inactive"]
    },

    "orders": {
        "title": "Orders",
        "table": "orders",
        "columns": [
            "id", "customer_name", "customer_phone",
            "total_amount", "order_status"
        ],
        "actions": [
            "Pending", "Processing", "Completed",
            "Delivered", "Cancelled"
        ]
    }
}

# --------------------------------------------------
# LOGIN
# --------------------------------------------------


@app.route("/", methods=["GET", "POST"])
@app.route("/login", methods=["GET", "POST"])
def login():

    if "admin_id" in session:
        return redirect(url_for("dashboard"))

    error = None

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        conn = get_db_connection()

        try:
            # Find admin using username only.
            admin = conn.execute(
                """
                SELECT * FROM admins
                WHERE username=?
                """,
                (username,)
            ).fetchone()

            if admin:

                stored_password = admin["password"]

                # First try secure hashed-password verification.
                try:
                    password_valid = check_password_hash(
                        stored_password,
                        password
                    )
                except (ValueError, TypeError):
                    password_valid = False

                # Support old plain-text passwords.
                if not password_valid and stored_password == password:

                    password_valid = True

                    # Convert old plain-text password into a hash.
                    new_hash = generate_password_hash(password)

                    conn.execute(
                        """
                        UPDATE admins
                        SET password=?
                        WHERE id=?
                        """,
                        (new_hash, admin["id"])
                    )

                    conn.commit()

                if password_valid:

                    session["admin_id"] = admin["id"]
                    session["admin_username"] = admin["username"]

                    return redirect(url_for("dashboard"))

            error = "Invalid username or password"

        finally:
            conn.close()

    return render_template("login.html", error=error)


# --------------------------------------------------
# DASHBOARD
# --------------------------------------------------


@app.route("/dashboard")
@admin_required
def dashboard():

    conn = get_db_connection()

    stats = {}

    try:
        # 1. Total customers
        stats["customers"] = get_count(
            conn,
            "users",
            "role='customer'"
        )

        # 2. Total sellers
        stats["sellers"] = get_count(conn, "sellers")

        # 3. Total riders
        stats["riders"] = get_count(conn, "riders")

        # 4. Total products
        stats["products"] = get_count(conn, "products")

        # 5. Total orders
        stats["orders"] = get_count(conn, "orders")

        # 6. Pending sellers
        stats["pending_sellers"] = get_count(
            conn, "sellers", "status='Pending'"
        )

        # 7. Pending riders
        stats["pending_riders"] = get_count(
            conn, "riders", "status='Pending'"
        )

        # 8. Pending products
        stats["pending_products"] = get_count(
            conn, "products", "status='Pending'"
        )

        # 9. Pending orders
        stats["pending_orders"] = get_count(
            conn, "orders", "order_status='Pending'"
        )

        # 10. Revenue
        # No payments table exists in our current database.
        stats["revenue"] = 0

        # 11. Completed / delivered orders
        stats["completed_orders"] = conn.execute(
            """
            SELECT COUNT(*)
            FROM orders
            WHERE order_status IN ('Completed', 'Delivered')
            """
        ).fetchone()[0]

        # 12. Open complaints
        # No complaints table exists in our current database.
        stats["open_complaints"] = 0

    finally:
        conn.close()

    return render_template(
        "dashboard.html",
        stats=stats
    )



# --------------------------------------------------
# SELLER AND RIDER LIST
# --------------------------------------------------


@app.route("/manage/<module>")
@admin_required
def manage_people(module):

    # Allow only these two modules
    if module not in ("sellers", "riders"):
        abort(404)

    search = request.args.get("search", "").strip()
    status = request.args.get("status", "All")

    # Actual database column names
    if module == "sellers":
        primary_key = "id"
        search_columns = ["full_name", "email", "phone", "shop_name"]
        title = "Sellers"
    else:
        primary_key = "rider_id"
        search_columns = ["full_name", "email", "phone"]
        title = "Riders"

    conn = get_db_connection()

    try:
        query = f"""
            SELECT *,
                   full_name AS name,
                   {primary_key} AS id
            FROM {module}
            WHERE 1=1
        """

        params = []

        # Search by name, email, phone and shop name (for sellers)
        if search:
            conditions = []

            for column in search_columns:
                conditions.append(f"{column} LIKE ?")

            query += " AND (" + " OR ".join(conditions) + ")"

            term = f"%{search}%"
            params.extend([term] * len(search_columns))

        # Filter by status
        if status != "All":
            query += " AND status=?"
            params.append(status)

        # Sort using the correct primary key
        query += f" ORDER BY {primary_key} DESC"

        rows = conn.execute(query, params).fetchall()

        total_records = conn.execute(
            f"SELECT COUNT(*) FROM {module}"
        ).fetchone()[0]

    finally:
        conn.close()

    return render_template(
        "people_list.html",
        rows=rows,
        module=module,
        title=title,
        search=search,
        selected_status=status,
        total_records=total_records
    )


# --------------------------------------------------
# SELLER / RIDER PROFILE DETAILS
# --------------------------------------------------


@app.route("/<module>/<int:record_id>")
@admin_required
def person_details(module, record_id):

    if module not in ("sellers", "riders"):
        abort(404)

    # Select the correct primary key
    primary_key = "id" if module == "sellers" else "rider_id"

    conn = get_db_connection()

    try:
        # Fetch seller or rider details
        person = conn.execute(
            f"""
            SELECT *,
                   {primary_key} AS id,
                   full_name AS name
            FROM {module}
            WHERE {primary_key}=?
            """,
            (record_id,)
        ).fetchone()

        if not person:
            abort(404)

        # Fetch documents
        document_fields = get_document_fields(module)

        if module == "sellers":

            # Seller documents are stored in sellers table
            documents = {
                label: person.get(field)
                for field, label in document_fields.items()
            }

        else:

            # Rider documents are stored separately
            rider_docs = conn.execute(
                """
                SELECT *
                FROM rider_documents
                WHERE rider_id=?
                """,
                (record_id,)
            ).fetchone()

            documents = {
                label: (
                    rider_docs.get(field)
                    if rider_docs else None
                )
                for field, label in document_fields.items()
            }

    finally:
        conn.close()

    return render_template(
        "person_details.html",
        person=person,
        module=module,
        title="Seller Details" if module == "sellers" else "Rider Details",
        documents=documents
    )



# --------------------------------------------------
# UPLOAD / REPLACE SELLER OR RIDER DOCUMENT
# --------------------------------------------------


@app.route(
    "/upload-document/<module>/<int:record_id>",
    methods=["POST"]
)
@admin_required
def upload_person_document(module, record_id):

    if module not in ("sellers", "riders"):
        abort(404)

    document_fields = get_document_fields(module)

    label_to_field = {
        label: field
        for field, label in document_fields.items()
    }

    selected_label = next(
        (
            label for label in label_to_field
            if request.files.get(label)
            and request.files.get(label).filename
        ),
        None
    )

    if not selected_label:
        flash("Please select a document to upload.")
        return redirect(url_for(
            "person_details",
            module=module,
            record_id=record_id
        ))

    field = label_to_field[selected_label]
    uploaded_file = request.files.get(selected_label)

    conn = get_db_connection()
    new_filename = None

    try:
        # Choose the correct table and ID column
        if module == "sellers":
            table = "sellers"
            primary_key = "id"
        else:
            table = "rider_documents"
            primary_key = "rider_id"

        # Check whether the person exists
        person_id_column = "id" if module == "sellers" else "rider_id"

        person = conn.execute(
            f"""
            SELECT * FROM {module}
            WHERE {person_id_column}=?
            """,
            (record_id,)
        ).fetchone()

        if not person:
            abort(404)

        # Check whether the document column exists
        columns = get_columns(conn, table)

        if field not in columns:
            flash(f"Database column missing: {field}")
            return redirect(url_for(
                "person_details",
                module=module,
                record_id=record_id
            ))

        # Get the previous document filename
        if module == "sellers":
            old_filename = person.get(field)
        else:
            rider_docs = conn.execute(
                """
                SELECT * FROM rider_documents
                WHERE rider_id=?
                """,
                (record_id,)
            ).fetchone()

            old_filename = (
                rider_docs.get(field)
                if rider_docs else None
            )

        # Save uploaded file
        try:
            new_filename = save_uploaded_file(uploaded_file)
        except ValueError as error:
            flash(str(error))
            return redirect(url_for(
                "person_details",
                module=module,
                record_id=record_id
            ))

        if not new_filename:
            flash("Please select a valid document.")
            return redirect(url_for(
                "person_details",
                module=module,
                record_id=record_id
            ))

        # Update seller document
        if module == "sellers":

            conn.execute(
                f"""
                UPDATE sellers
                SET {field}=?
                WHERE id=?
                """,
                (new_filename, record_id)
            )

        # Insert or update rider document
        else:

            conn.execute(
                f"""
                INSERT INTO rider_documents (rider_id, {field})
                VALUES (?, ?)
                ON DUPLICATE KEY UPDATE
                {field}=VALUES({field})
                """,
                (record_id, new_filename)
            )

        conn.commit()

        # Delete previous file after successful database update
        if old_filename:
            old_safe_name = secure_filename(old_filename)

            if old_safe_name == old_filename:
                old_path = os.path.join(
                    app.config["UPLOAD_FOLDER"],
                    old_safe_name
                )

                if os.path.isfile(old_path):
                    try:
                        os.remove(old_path)
                    except OSError:
                        pass

        flash(f"{selected_label} uploaded successfully!")

    except Exception:
        conn.rollback()

        if new_filename:
            new_path = os.path.join(
                app.config["UPLOAD_FOLDER"],
                new_filename
            )

            if os.path.isfile(new_path):
                try:
                    os.remove(new_path)
                except OSError:
                    pass

        raise

    finally:
        conn.close()

    return redirect(url_for(
        "person_details",
        module=module,
        record_id=record_id
    ))

# --------------------------------------------------
# APPROVE / REJECT / BLOCK SELLER OR RIDER
# --------------------------------------------------

@app.route("/review/<module>/<int:record_id>", methods=["POST"])
@admin_required
def review_person(module, record_id):

    if module not in ("sellers", "riders"):
        abort(404)

    action = request.form.get("action", "").strip()
    reason = request.form.get("rejection_reason", "").strip()

    allowed_actions = [
        "Approved", "Rejected", "Blocked", "Pending"
    ]

    if action not in allowed_actions:
        flash("Invalid status selected.")
        return redirect(url_for(
            "person_details", module=module, record_id=record_id
        ))

    primary_key = "id" if module == "sellers" else "rider_id"

    conn = get_db_connection()

    try:
        person = conn.execute(
            f"SELECT * FROM {module} WHERE {primary_key}=?",
            (record_id,)
        ).fetchone()

        if not person:
            abort(404)

        if action in ("Rejected", "Blocked") and not reason:
            flash("Please enter a reason.")
            return redirect(url_for(
                "person_details", module=module, record_id=record_id
            ))

        if module == "sellers":
            conn.execute(
                """
                UPDATE sellers
                SET status=?, reason=?
                WHERE id=?
                """,
                (
                    action,
                    reason if action in ("Rejected", "Blocked") else None,
                    record_id
                )
            )

        else:
            # Riders table has status, but no reason or reapply_after column.
            conn.execute(
                """
                UPDATE riders
                SET status=?
                WHERE rider_id=?
                """,
                (action, record_id)
            )
        print("RIDER APPROVAL DEBUG:")
        print("Rider ID:", record_id)
        print("Selected action:", action)

        updated_rider = conn.execute(
            "SELECT rider_id, full_name, status FROM riders WHERE rider_id=?",
            (record_id,)
        ).fetchone()

        print("Updated rider:", updated_rider)

        conn.commit()

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()

    flash(f"{module[:-1].title()} status updated successfully!")

    return redirect(url_for(
        "person_details",
        module=module,
        record_id=record_id
    ))


# --------------------------------------------------
# SECURE DOCUMENT VIEW
# --------------------------------------------------

@app.route("/documents/<filename>")
@admin_required
def view_document(filename):

    safe_name = secure_filename(filename)

    if safe_name != filename:
        abort(404)

    file_path = os.path.join(
        app.config["UPLOAD_FOLDER"], safe_name
    )

    if not os.path.isfile(file_path):
        abort(404)

    return send_from_directory(
        app.config["UPLOAD_FOLDER"],
        safe_name,
        as_attachment=False
    )


# --------------------------------------------------
# CUSTOMER DETAILS AND ORDER HISTORY
# --------------------------------------------------


@app.route("/customers/<int:record_id>")
@admin_required
def customer_details(record_id):

    conn = get_db_connection()

    try:
        customer = conn.execute(
            """
            SELECT *, mobile AS phone
            FROM users
            WHERE id=? AND role='customer'
            """,
            (record_id,)
        ).fetchone()

        if not customer:
            abort(404)

        orders = conn.execute(
            """
            SELECT *
            FROM orders
            WHERE customer_phone=?
            ORDER BY id DESC
            """,
            (customer["mobile"],)
        ).fetchall()

        order_count = len(orders)

        total_spending = conn.execute(
            """
            SELECT COALESCE(SUM(total_amount), 0)
            FROM orders
            WHERE customer_phone=?
              AND order_status != 'Cancelled'
            """,
            (customer["mobile"],)
        ).fetchone()[0]

    finally:
        conn.close()

    return render_template(
        "customer_details.html",
        customer=customer,
        orders=orders,
        order_count=order_count,
        total_spending=total_spending
    )

# --------------------------------------------------
# CUSTOMERS / PRODUCTS / ORDERS / PAYMENTS / COMPLAINTS
# --------------------------------------------------


@app.route("/manage/<module>/records", methods=["GET", "POST"])
@admin_required
def manage_records(module):

    if module not in MODULES:
        abort(404)

    config = MODULES[module]
    table = config["table"]
    status_column = "order_status" if module == "orders" else "status"

    conn = get_db_connection()

    try:
        search = request.args.get("search", "").strip()

        if request.method == "POST":
            action = request.form.get("action", "").strip()
            record_id = request.form.get("record_id", "").strip()

            if not record_id.isdigit():
                flash("Invalid record selected.")
                return redirect(url_for("manage_records", module=module))

            if action == "delete":
                conn.execute(
                    f"DELETE FROM {table} WHERE id=?",
                    (record_id,)
                )
                conn.commit()
                flash("Record deleted successfully!")
                return redirect(url_for("manage_records", module=module))

            new_status = request.form.get("new_status", "").strip()

            if not new_status and action in config["actions"]:
                new_status = action

            if (
                new_status in config["actions"]
                and status_column in get_columns(conn, table)
            ):
                conn.execute(
                    f"""
                    UPDATE {table}
                    SET {status_column}=?
                    WHERE id=?
                    """,
                    (new_status, record_id)
                )
                conn.commit()
                flash("Status updated successfully!")
            else:
                flash("Unable to update this record.")

            return redirect(url_for("manage_records", module=module))


        query = f"SELECT * FROM {table} WHERE 1=1"
        count_query = f"SELECT COUNT(*) FROM {table} WHERE 1=1"

        params = []
        count_params = []

        

        

        # Show only customers, not sellers/riders
        if module == "customers":
            query += " AND role='customer'"
            count_query += " AND role='customer'"

       
        

        actual_columns = get_columns(conn, table)
        display_columns = [
            column for column in config["columns"]
            if column in actual_columns
        ]

        searchable_columns = [
            column for column in display_columns
            if column != "id"
        ]
        if search and searchable_columns:
            conditions = [
                f"CAST({column} AS TEXT) LIKE ?"
                for column in searchable_columns
            ]

            search_condition = (
                " AND (" + " OR ".join(conditions) + ")"
            )

            query += search_condition
            count_query += search_condition

            search_values = [f"%{search}%"] * len(conditions)

            params.extend(search_values)
            count_params.extend(search_values)
         

        

        query += " ORDER BY id DESC"

        rows = conn.execute(query, params).fetchall()
        total_records = conn.execute(
            count_query, count_params
        ).fetchone()[0]

    finally:
        conn.close()

    return render_template(
        "manage_records.html",
        title=config["title"],
        module=module,
        columns=display_columns,
        actions=config["actions"],
        rows=rows,
        search=search,
        total_records=total_records,
        status_column=status_column
    )


# --------------------------------------------------
# ORDER DETAILS
# --------------------------------------------------

@app.route("/orders/<int:order_id>")
@admin_required
def order_details(order_id):

    conn = get_db_connection()

    try:
        order = conn.execute(
            "SELECT * FROM orders WHERE id=?",
            (order_id,)
        ).fetchone()

        if not order:
            abort(404)

        items = conn.execute(
            """
            SELECT
                oi.*,
                p.name AS product_name
            FROM order_items oi
            LEFT JOIN products p
                ON oi.product_id = p.id
            WHERE oi.order_id=?
            """,
            (order_id,)
        ).fetchall()

        customer = conn.execute(
            """
            SELECT *
            FROM users
            WHERE mobile=? AND role='customer'
            """,
            (order["customer_phone"],)
        ).fetchone()

    finally:
        conn.close()

    return render_template(
        "order_details.html",
        order=order,
        customer=customer,
        items=items,
        payment=None
    )


# --------------------------------------------------


# --------------------------------------------------
# REPORTS
# --------------------------------------------------

@app.route("/reports")
@admin_required
def reports():

    conn = get_db_connection()

    try:
        report = {
            "total_customers": get_count(
                conn, "users", "role='customer'"
            ),

            "total_sellers": get_count(conn, "sellers"),

            "total_riders": get_count(conn, "riders"),

            "total_products": get_count(conn, "products"),

            "total_orders": get_count(conn, "orders"),

            "completed_orders": 0,

            "cancelled_orders": 0,

            "total_revenue": 0
        }

        # Completed orders
        report["completed_orders"] = conn.execute(
            """
            SELECT COUNT(*)
            FROM orders
            WHERE order_status IN ('Completed', 'Delivered')
            """
        ).fetchone()[0]

        # Cancelled orders
        report["cancelled_orders"] = conn.execute(
            """
            SELECT COUNT(*)
            FROM orders
            WHERE order_status = 'Cancelled'
            """
        ).fetchone()[0]

        # Order value excluding cancelled orders.
        # This is not verified payment revenue.
        report["total_revenue"] = conn.execute(
            """
            SELECT COALESCE(SUM(total_amount), 0)
            FROM orders
            WHERE order_status != 'Cancelled'
            """
        ).fetchone()[0]

        return render_template(
            "reports.html",
            report=report
        )

    finally:
        conn.close()


# --------------------------------------------------
# NOTIFICATIONS
# --------------------------------------------------


@app.route("/notifications", methods=["GET", "POST"])
@admin_required
def notifications():

    conn = get_db_connection()

    try:
        if request.method == "POST":

            action = request.form.get("action", "").strip()

            if action == "create":
                title = request.form.get("title", "").strip()
                message = request.form.get("message", "").strip()

                if not title or not message:
                    flash("Please enter title and message.")
                else:
                    sellers = conn.execute(
                        "SELECT id FROM sellers"
                    ).fetchall()

                    for seller in sellers:
                        conn.execute(
                            """
                            INSERT INTO notifications
                            (seller_id, title, message)
                            VALUES (?, ?, ?)
                            """,
                            (seller["id"], title, message)
                        )

                    conn.commit()
                    flash("Announcement sent to all sellers!")

            elif action == "delete":
                notification_id = request.form.get(
                    "notification_id", ""
                ).strip()

                if notification_id.isdigit():
                    conn.execute(
                        "DELETE FROM notifications WHERE id=?",
                        (int(notification_id),)
                    )
                    conn.commit()
                    flash("Notification deleted successfully!")

            return redirect(url_for("notifications"))

        rows = conn.execute(
            """
            SELECT n.*, s.shop_name
            FROM notifications n
            LEFT JOIN sellers s ON n.seller_id=s.id
            ORDER BY n.id DESC
            """
        ).fetchall()

        analytics = {
            "total": len(rows),
            "all_users": 0,
            "customers": 0,
            "sellers": len(rows),
            "riders": 0
        }

    finally:
        conn.close()

    return render_template(
        "notifications.html",
        rows=rows,
        analytics=analytics
    )



# --------------------------------------------------
# SETTINGS
# --------------------------------------------------


@app.route("/settings", methods=["GET", "POST"])
@admin_required
def settings():

    conn = get_db_connection()

    try:
        admin = conn.execute(
            """
            SELECT * FROM admins
            WHERE id=?
            """,
            (session["admin_id"],)
        ).fetchone()

        message = ""

        if request.method == "POST":

            username = request.form.get("username", "").strip()
            old_password = request.form.get("old_password", "")
            new_password = request.form.get("new_password", "")

            if not username or not old_password or not new_password:
                message = "Please fill all fields."

            elif len(new_password) < 4:
                message = "New password must contain at least 4 characters."

            elif not admin:
                message = "Admin account not found."

            else:
                stored_password = admin["password"]

                # Check whether the current password is correct.
                try:
                    password_valid = check_password_hash(
                        stored_password,
                        old_password
                    )
                except (ValueError, TypeError):
                    password_valid = False

                # Support existing plain-text passwords.
                if not password_valid and stored_password == old_password:
                    password_valid = True

                if not password_valid:
                    message = "Current password is incorrect."

                else:
                    try:
                        hashed_password = generate_password_hash(
                            new_password
                        )

                        conn.execute(
                            """
                            UPDATE admins
                            SET username=?, password=?
                            WHERE id=?
                            """,
                            (
                                username,
                                hashed_password,
                                session["admin_id"]
                            )
                        )

                        conn.commit()

                        session["admin_username"] = username

                        message = "Settings updated successfully!"

                        admin = conn.execute(
                            """
                            SELECT * FROM admins
                            WHERE id=?
                            """,
                            (session["admin_id"],)
                        ).fetchone()

                    except IntegrityError:
                        conn.rollback()
                        message = "Username already exists."

        return render_template(
            "settings.html",
            admin=admin,
            message=message
        )

    finally:
        conn.close()



# --------------------------------------------------
# LOGOUT
# --------------------------------------------------

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# --------------------------------------------------
# RUN APPLICATION
# --------------------------------------------------

if __name__ == "__main__":
    init_db()
    app.run(debug=True,port=5003)
