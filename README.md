## StyleLane (Local MVP)

**Tech**: Python (Flask), SQLite, HTML, CSS, JavaScript.

### What you get
- **Role-based login**: Admin / Store Manager / Supplier
- **Admin**: overview of users, stores, inventory, restock requests
- **Store Manager**: manage store inventory, create restock requests
- **Supplier**: view requests assigned to them, update shipment status

### Setup (Windows PowerShell)

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### Create DB + seed demo data

```powershell
python app.py --init-db
python app.py --seed
```

### Run

```powershell
python app.py
```

Open `http://127.0.0.1:5000`

### Demo accounts
- **Admin**: `admin@stylelane.local` / `admin123`
- **Store Manager**: `manager@stylelane.local` / `manager123`
- **Supplier**: `supplier@stylelane.local` / `supplier123`

