import streamlit as st
from pymongo import MongoClient
import bcrypt

# ----------------- DATABASE CONNECTION -----------------
mongo_uri = st.secrets["mongo"]["uri"]
client = MongoClient(mongo_uri)
db = client["online_store"]
users_col = db["users"]
products_col = db["products"]

# ----------------- APP CONFIG -----------------
st.set_page_config(page_title="Online Store", layout="centered")

# ----------------- HELPER FUNCTIONS -----------------
def create_user(username, password, role="user"):
    """Create a new user with hashed password."""
    if users_col.find_one({"username": username}):
        return False
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    users_col.insert_one({"username": username, "password": hashed, "role": role})
    return True

def authenticate(username, password):
    """Authenticate user credentials."""
    user = users_col.find_one({"username": username})
    if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
        return user
    return None

def add_product(name, price):
    """Add a new product."""
    if products_col.find_one({"name": name}):
        return False
    products_col.insert_one({"name": name, "price": price})
    return True

def get_products():
    """Fetch all products."""
    return list(products_col.find({}, {"_id": 0}))

# ----------------- LOGIN PAGE -----------------
def login_page():
    st.title("🛍️ Online Store Login")

    login_choice = st.radio("Login as:", ["Admin", "User"])
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        user = authenticate(username, password)
        if user:
            if login_choice.lower() == user["role"]:
                st.session_state["user"] = user
                st.success(f"✅ Logged in as {user['role']}")
                st.rerun()
            else:
                st.error("You selected the wrong role.")
        else:
            st.error("Invalid username or password.")

# ----------------- ADMIN DASHBOARD -----------------
def admin_dashboard():
    st.title("👩‍💼 Admin Dashboard")

    st.subheader("Create New User")
    new_user = st.text_input("Enter new username")
    new_pass = st.text_input("Enter new password", type="password")
    if st.button("Create User"):
        if create_user(new_user, new_pass, role="user"):
            st.success(f"User '{new_user}' created successfully.")
        else:
            st.warning("User already exists.")

    st.subheader("Add Product")
    product_name = st.text_input("Product name")
    product_price = st.number_input("Product price ($)", min_value=0.0, step=0.01)
    if st.button("Add Product"):
        if add_product(product_name, product_price):
            st.success(f"Product '{product_name}' added successfully.")
        else:
            st.warning("Product already exists.")

    st.subheader("📦 Product List")
    products = get_products()
    if products:
        st.table(products)
    else:
        st.info("No products found.")

    if st.button("Logout"):
        del st.session_state["user"]
        st.rerun()

# ----------------- USER DASHBOARD -----------------
def user_dashboard():
    st.title("🛒 Product Catalog")

    products = get_products()
    if not products:
        st.info("No products available yet.")
        return

    for prod in products:
        col1, col2, col3 = st.columns([3, 1, 1])
        with col1:
            st.write(f"**{prod['name']}**")
        with col2:
            st.write(f"${prod['price']:.2f}")
        with col3:
            if st.button(f"Add to Cart - {prod['name']}"):
                if "cart" not in st.session_state:
                    st.session_state["cart"] = []
                st.session_state["cart"].append(prod)
                st.success(f"Added {prod['name']} to cart.")

    if "cart" in st.session_state and st.session_state["cart"]:
        st.subheader("🛍️ Your Cart")
        total = sum(item["price"] for item in st.session_state["cart"])
        for item in st.session_state["cart"]:
            st.write(f"- {item['name']} (${item['price']:.2f})")
        st.write(f"**Total: ${total:.2f}**")

        if st.button("Buy"):
            st.success("✅ Order placed successfully!")
            del st.session_state["cart"]

    if st.button("Logout"):
        del st.session_state["user"]
        st.rerun()

# ----------------- MAIN APP -----------------
def main():
    if "user" not in st.session_state:
        login_page()
    else:
        user = st.session_state["user"]
        if user["role"] == "admin":
            admin_dashboard()
        else:
            user_dashboard()

if __name__ == "__main__":
    # Create the admin account if it doesn't exist
    if not users_col.find_one({"username": "bhumika", "role": "admin"}):
        create_user("bhumika", "bhumika01", role="admin")
        print("✅ Admin account created: username='bhumika', password='bhumika01'")
    main()
