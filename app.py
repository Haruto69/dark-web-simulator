# app.py - Safe Dark Web Risk Simulator (educational) with Funnel Tracking

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
import random
import uuid

app = Flask(__name__)
app.secret_key = "change-this-secret-in-lab"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///simulator.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# --- Models ---

class Product(db.Model):
    __tablename__ = 'product'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120))
    description = db.Column(db.Text)
    price = db.Column(db.Float)
    image = db.Column(db.String(256))

class DemoFile(db.Model):
    __tablename__ = 'demo_file'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(256))
    status = db.Column(db.String(50), default='available')  # available / encrypted
    remark = db.Column(db.String(256), default='')

class SimulatedCredential(db.Model):
    __tablename__ = 'simulated_credential'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(256))
    password = db.Column(db.String(256))
    note = db.Column(db.String(256))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    simulated = db.Column(db.Boolean, default=True)

class PhishingFunnel(db.Model):
    __tablename__ = 'phishing_funnel'
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.String(100))
    stage = db.Column(db.String(50))  # 'marketplace', 'payment', 'credentials'
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    details = db.Column(db.String(500))

class RansomwareFunnel(db.Model):
    __tablename__ = 'ransomware_funnel'
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.String(100))
    stage = db.Column(db.String(50))  # 'menu', 'interaction', 'triggered'
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    details = db.Column(db.String(500))

# Session tracking
@app.before_request
def ensure_session_id():
    if 'session_id' not in session:
        session['session_id'] = str(uuid.uuid4())

def init_db():
    db.create_all()
    
    # Clear old data (optional - comment out if you want to keep data between restarts)
    Product.query.delete()
    DemoFile.query.delete()
    
    # Initialize demo files for ransomware simulation
    files = [
        DemoFile(name="employee_list.csv"),
        DemoFile(name="sample_financials.xlsx"),
        DemoFile(name="project_docs.pdf"),
        DemoFile(name="family_photos_2024.zip"),
        DemoFile(name="tax_returns_2023.pdf"),
        DemoFile(name="passwords_backup.txt"),
        DemoFile(name="business_contract.docx"),
        DemoFile(name="vacation_photos.jpg"),
        DemoFile(name="thesis_final_draft.docx"),
        DemoFile(name="cryptocurrency_keys.txt"),
        DemoFile(name="bank_statements.pdf"),
        DemoFile(name="client_database.xlsx"),
        DemoFile(name="personal_diary.docx"),
        DemoFile(name="wedding_photos.zip"),
        DemoFile(name="medical_records.pdf")
    ]
    
    for file in files:
        db.session.add(file)
    
    # Initialize products
    products = [
        # Equipment Section
        Product(
            name="AK-47 Replica",
            description="Detailed replica for collectors.",
            price=299.99,
            image="images/products/ak47.jpeg"
        ),
        Product(
            name="Multi-Purpose Calculator",
            description="Advanced calculation device for both botanical measurements and general use.",
            price=149.99,
            image="images/products/calc.jpeg"
        ),
        Product(
            name="Professional Drone",
            description="High-performance aerial device.",
            price=2999.99,
            image="images/products/drone.jpeg"
        ),
        Product(
            name="Glock 19 Replica",
            description="Collector's item replica.",
            price=199.99,
            image="images/products/glock19.jpeg"
        ),
        Product(
            name="M16 Model",
            description="Detailed model for display.",
            price=399.99,
            image="images/products/m16.jpeg"
        ),
        Product(
            name="MH12 Tactical",
            description="High-precision tactical replica MH12 for collectors and display.",
            price=1299.99,
            image="images/products/MH12.jpeg"
        ),
        Product(
            name="AWM Sniper Replica",
            description="Accurate AWM replica model suitable for exhibition and educational displays.",
            price=1599.99,
            image="images/products/AWM.jpeg"
        ),
        Product(
            name="Guns Collection 1",
            description="Mixed collection of classic firearm replicas for collectors.",
            price=749.99,
            image="images/products/guns1.jpeg"
        ),
        # Plants Section
        Product(
            name="Special Blend",
            description="Premium crystalline botanical extract.",
            price=899.99,
            image="images/products/coke1.jpeg"
        ),
        Product(
            name="Crystal Formation",
            description="Naturally formed crystal specimens.",
            price=1299.99,
            image="images/products/crystals.jpeg"
        ),
        Product(
            name="Plant Nutrient Injector",
            description="Specialized botanical feeding system.",
            price=449.99,
            image="images/products/injection.jpeg"
        ),
        Product(
            name="Rare Plant Collection A",
            description="Exotic botanical specimens.",
            price=499.99,
            image="images/products/plant1.jpeg"
        ),
        Product(
            name="Rare Plant Collection B",
            description="Premium plant varieties.",
            price=599.99,
            image="images/products/plant2.jpeg"
        ),
        Product(
            name="Rare Plant Collection C",
            description="Exclusive botanical selection.",
            price=699.99,
            image="images/products/plant3.jpeg"
        ),
        Product(
            name="Herbal Blend",
            description="Special aromatic mixture.",
            price=349.99,
            image="images/products/smoke.jpeg"
        )
    ]
    
    for product in products:
        db.session.add(product)
    
    db.session.commit()

with app.app_context():
    init_db()

@app.route("/")
def index():
    q = request.args.get('q', '').lower()
    results = []
    navigation_links = []
    
    # Mock pages for search results
    mock_pages = [
        # Plant-related pages
        {
            'slug': 'exotic-plants',
            'title': 'Exotic Plants Market',
            'content': 'Rare and exotic botanical specimens from around the world. Premium selection of unique plants and herbs.',
            'category': 'plants',
            'url': '/marketplace/plants'
        },
        {
            'slug': 'rare-specimens',
            'title': 'Rare Plant Specimens',
            'content': 'Premium collection of hard-to-find botanical varieties. Exclusive selection of rare plants and crystalline extracts.',
            'category': 'plants',
            'url': '/marketplace/plants'
        },
        {
            'slug': 'herbal-market',
            'title': 'Premium Herbal Market',
            'content': 'Special aromatic mixtures and botanical blends. Features rare plant collections.',
            'category': 'plants',
            'url': '/marketplace/plants'
        },
        {
            'slug': 'crystal-botanicals',
            'title': 'Crystal Botanical Exchange',
            'content': 'Specialized marketplace for crystalline botanical specimens and extracts.',
            'category': 'plants',
            'url': '/marketplace/plants'
        },
        {
            'slug': 'plant-nutrients',
            'title': 'Plant Nutrient Systems',
            'content': 'Advanced feeding and nutrient delivery systems for specialized plant cultivation.',
            'category': 'plants',
            'url': '/marketplace/plants'
        },
        {
            'slug': 'smoke-blends',
            'title': 'Aromatic Smoke Blends',
            'content': 'Curated collection of premium aromatic blends and mixtures.',
            'category': 'plants',
            'url': '/marketplace/plants'
        },
        {
            'slug': 'botanical-research',
            'title': 'Botanical Research Supplies',
            'content': 'Specialized equipment and supplies for botanical research and experimentation.',
            'category': 'plants',
            'url': '/marketplace/plants'
        },
        {
            'slug': 'plant-extracts',
            'title': 'Premium Plant Extracts',
            'content': 'High-quality botanical extracts and concentrates from rare specimens.',
            'category': 'plants',
            'url': '/marketplace/plants'
        },
        {
            'slug': 'herb-collection',
            'title': 'Rare Herb Collection',
            'content': 'Exclusive collection of rare and exotic herbal specimens.',
            'category': 'plants',
            'url': '/marketplace/plants'
        },
        {
            'slug': 'botanical-lab',
            'title': 'Botanical Laboratory',
            'content': 'Professional equipment for botanical processing and research.',
            'category': 'plants',
            'url': '/marketplace/plants'
        },
        # Equipment-related pages
        {
            'slug': 'tactical-gear',
            'title': 'Tactical Equipment Market',
            'content': 'Professional grade tactical equipment and accessories.',
            'category': 'equipment',
            'url': '/marketplace/weapons'
        },
        {
            'slug': 'military-surplus',
            'title': 'Military Equipment Market',
            'content': 'Specialized military-grade equipment and collectibles.',
            'category': 'equipment',
            'url': '/marketplace/weapons'
        },
        {
            'slug': 'weapon-collect',
            'title': 'Equipment Collection Market',
            'content': 'Premium collection of specialized equipment and replicas.',
            'category': 'equipment',
            'url': '/marketplace/weapons'
        },
        {
            'slug': 'sniper-gear',
            'title': 'Precision Equipment Market',
            'content': 'High-precision tactical equipment and accessories.',
            'category': 'equipment',
            'url': '/marketplace/weapons'
        },
        {
            'slug': 'combat-gear',
            'title': 'Combat Equipment Exchange',
            'content': 'Professional combat equipment and tactical gear.',
            'category': 'equipment',
            'url': '/marketplace/weapons'
        },
        {
            'slug': 'collector-items',
            'title': 'Collector Equipment Gallery',
            'content': 'Rare and exclusive collector-grade equipment and replicas.',
            'category': 'equipment',
            'url': '/marketplace/weapons'
        },
        {
            'slug': 'aerial-equipment',
            'title': 'Aerial Equipment Market',
            'content': 'Professional aerial devices and related equipment.',
            'category': 'equipment',
            'url': '/marketplace/weapons'
        },
        {
            'slug': 'tactical-accessories',
            'title': 'Tactical Accessories Exchange',
            'content': 'Specialized accessories for tactical equipment.',
            'category': 'equipment',
            'url': '/marketplace/weapons'
        },
        {
            'slug': 'defense-gear',
            'title': 'Defense Equipment Market',
            'content': 'Professional defense equipment and tactical gear.',
            'category': 'equipment',
            'url': '/marketplace/weapons'
        },
        {
            'slug': 'equipment-parts',
            'title': 'Equipment Parts Exchange',
            'content': 'Specialized parts and components for tactical equipment.',
            'category': 'equipment',
            'url': '/marketplace/weapons'
        },
        # Tools pages
        {
            'slug': 'hacking-tools',
            'title': 'Premium Hacking Tools',
            'content': 'Professional exploitation tools and penetration testing suites. Download the most advanced hacking software used by professionals worldwide.',
            'category': 'tools',
            'url': '/marketplace/tools'
        },
        {
            'slug': 'exploit-kits',
            'title': 'Exploit Kits Market',
            'content': 'Advanced exploitation frameworks and zero-day vulnerabilities. Professional hacking tools.',
            'category': 'tools',
            'url': '/marketplace/tools'
        },
        # Storage page
        {
            'slug': 'secure-storage',
            'title': 'Secure File Storage',
            'content': 'Browse and manage your encrypted files. Access your secure document storage system.',
            'category': 'storage',
            'url': '/files/browser'
        }
    ]
    
    if q:
        # Keywords for better categorization
        plant_keywords = ['plant', 'botanic', 'herb', 'crystal', 'specimen', 'extract', 'blend']
        equipment_keywords = ['equipment', 'weapon', 'tactical', 'military', 'gear', 'device']
        tools_keywords = ['hack', 'tool', 'exploit', 'crack', 'penetration', 'software']
        
        # Check if query matches category keywords
        is_plant_search = any(keyword in q for keyword in plant_keywords)
        is_equipment_search = any(keyword in q for keyword in equipment_keywords)
        is_tools_search = any(keyword in q for keyword in tools_keywords)
        
        # Define navigation links based on search category
        if is_plant_search:
            results = [page for page in mock_pages if page['category'] == 'plants']
            navigation_links = [{'title': 'Plants & Botanicals', 'url': '/marketplace/plants'}]
        elif is_equipment_search:
            results = [page for page in mock_pages if page['category'] == 'equipment']
            navigation_links = [{'title': 'Equipment & Accessories', 'url': '/marketplace/weapons'}]
        elif is_tools_search:
            results = [page for page in mock_pages if page['category'] == 'tools']
            navigation_links = [{'title': 'Hacking Tools', 'url': '/marketplace/tools'}]
        else:
            # Regular search in title and content
            results = [page for page in mock_pages if q in page['title'].lower() or q in page['content'].lower()]
            navigation_links = [
                {'title': 'Plants & Botanicals', 'url': '/marketplace/plants'},
                {'title': 'Equipment & Accessories', 'url': '/marketplace/weapons'},
                {'title': 'Hacking Tools', 'url': '/marketplace/tools'}
            ]
    else:
        # Show all navigation links if no search query
        navigation_links = [
            {'title': 'Plants & Botanicals', 'url': '/marketplace/plants'},
            {'title': 'Equipment & Accessories', 'url': '/marketplace/weapons'},
            {'title': 'Hacking Tools', 'url': '/marketplace/tools'}
        ]
    
    return render_template("index.html", results=results, q=q, navigation_links=navigation_links)

@app.route("/marketplace/plants")
def marketplace_plants():
    products = Product.query.filter(
        db.or_(
            Product.image.like('%calc%'),
            Product.image.like('%coke%'),
            Product.image.like('%crystals%'),
            Product.image.like('%injection%'),
            Product.image.like('%plant%'),
            Product.image.like('%smoke%')
        )
    ).all()
    return render_template("marketplace.html", products=products, category="Plants & Botanicals")

@app.route("/marketplace/weapons")
def marketplace_weapons():
    products = Product.query.filter(
        db.or_(
            Product.image.like('%ak%'),
            Product.image.like('%drone%'),
            Product.image.like('%glock%'),
            Product.image.like('%m16%'),
            Product.image.like('%MH12%'),
            Product.image.like('%AWM%'),
            Product.image.like('%guns1%')
        )
    ).all()
    return render_template("marketplace.html", products=products, category="Equipment & Accessories")

# RANSOMWARE ROUTES

@app.route("/ransomware/menu")
def ransomware_menu():
    """Main menu for choosing ransomware simulation type - STAGE 1"""
    # Track Stage 1: Visited ransomware menu
    funnel = RansomwareFunnel(
        session_id=session.get('session_id'),
        stage='menu',
        details="Visited ransomware simulation menu"
    )
    db.session.add(funnel)
    db.session.commit()
    
    return render_template("ransomware_menu.html")

@app.route("/marketplace/tools")
def marketplace_tools():
    """Option 1: Fake hacking tools marketplace - STAGE 2"""
    # Track Stage 2: Viewed hacking tools
    funnel = RansomwareFunnel(
        session_id=session.get('session_id'),
        stage='interaction',
        details="Viewed hacking tools marketplace"
    )
    db.session.add(funnel)
    db.session.commit()
    
    fake_tools = [
        {
            'id': 1,
            'name': 'MetaSploit Pro Ultimate',
            'description': 'Advanced exploitation framework. Penetrate any system. Includes all premium modules and zero-day exploits.',
            'price': 499.99,
            'downloads': random.randint(500, 2000),
            'rating': 4.8
        },
        {
            'id': 2,
            'name': 'Network Cracker Suite',
            'description': 'Crack WiFi passwords, bypass firewalls, access any network. Military-grade encryption breaking.',
            'price': 299.99,
            'downloads': random.randint(800, 1500),
            'rating': 4.9
        },
        {
            'id': 3,
            'name': 'Database Exploit Kit',
            'description': 'Extract data from any SQL/NoSQL database. Includes zero-days for MongoDB, MySQL, PostgreSQL.',
            'price': 899.99,
            'downloads': random.randint(300, 900),
            'rating': 4.7
        },
        {
            'id': 4,
            'name': 'RAT Command Center',
            'description': 'Remote access trojan with keylogger, screen capture, webcam access. Undetectable by antivirus.',
            'price': 699.99,
            'downloads': random.randint(600, 1200),
            'rating': 4.6
        },
        {
            'id': 5,
            'name': 'Credential Stealer Pro',
            'description': 'Harvest credentials from browsers, email clients, FTP applications. Works on all platforms.',
            'price': 399.99,
            'downloads': random.randint(900, 1800),
            'rating': 4.8
        },
        {
            'id': 6,
            'name': 'Crypto Miner Botnet',
            'description': 'Deploy mining software across networks. Includes DDoS capabilities and proxy chaining.',
            'price': 1299.99,
            'downloads': random.randint(200, 600),
            'rating': 4.5
        },
        {
            'id': 7,
            'name': 'Mobile Spy Suite',
            'description': 'Complete mobile surveillance. Track location, read messages, access camera remotely.',
            'price': 549.99,
            'downloads': random.randint(700, 1400),
            'rating': 4.7
        },
        {
            'id': 8,
            'name': 'Ransomware Builder Kit',
            'description': 'Build custom ransomware with GUI interface. Automated Bitcoin payment system included.',
            'price': 1999.99,
            'downloads': random.randint(150, 400),
            'rating': 4.9
        }
    ]
    
    return render_template("hacking_tools.html", tools=fake_tools)

@app.route("/download/tool/<int:tool_id>")
def download_tool(tool_id):
    """Show fake download progress screen"""
    return render_template("ransomware_download.html", tool_id=tool_id)

@app.route("/files/browser")
def file_browser():
    """Option 2: File browser with encryption trigger - STAGE 2"""
    # Track Stage 2: Viewed file browser
    funnel = RansomwareFunnel(
        session_id=session.get('session_id'),
        stage='interaction',
        details="Accessed file browser"
    )
    db.session.add(funnel)
    db.session.commit()
    
    files = DemoFile.query.all()
    return render_template("file_browser.html", files=files)

@app.route("/ransomware/trigger")
def ransomware_trigger():
    """Trigger ransomware from file browser (Option 2) - STAGE 3"""
    # Track Stage 3: Triggered ransomware
    funnel = RansomwareFunnel(
        session_id=session.get('session_id'),
        stage='triggered',
        details="Interacted with file browser - ransomware triggered"
    )
    db.session.add(funnel)
    
    # Mark files as encrypted
    files = DemoFile.query.all()
    for f in files:
        f.status = "encrypted"
        f.remark = f"Encrypted by LockBit Simulator - {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}"
    
    db.session.commit()
    
    # Generate fake Bitcoin address
    bitcoin_address = "1" + ''.join(random.choices('123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz', k=33))
    ransom_amount = random.choice([0.5, 1.0, 1.5, 2.0])
    
    return render_template("ransomware_screen.html",
                         bitcoin_address=bitcoin_address,
                         ransom_amount=ransom_amount,
                         encrypted_files=files,
                         source='browser')

@app.route("/ransomware/activate")
def ransomware_activate():
    """Trigger ransomware from hacking tools download (Option 1) - STAGE 3"""
    # Track Stage 3: Triggered ransomware
    funnel = RansomwareFunnel(
        session_id=session.get('session_id'),
        stage='triggered',
        details="Downloaded fake hacking tool - ransomware triggered"
    )
    db.session.add(funnel)
    
    # Mark files as encrypted
    files = DemoFile.query.all()
    for f in files:
        f.status = "encrypted"
        f.remark = f"Encrypted by WannaCry Simulator - {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}"
    
    db.session.commit()
    
    # Generate fake Bitcoin address
    bitcoin_address = "1" + ''.join(random.choices('123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz', k=33))
    ransom_amount = random.choice([1.0, 1.5, 2.0, 2.5])
    
    return render_template("ransomware_screen.html",
                         bitcoin_address=bitcoin_address,
                         ransom_amount=ransom_amount,
                         encrypted_files=files,
                         source='download')

@app.route("/ransomware/screen")
def ransomware_screen():
    """Direct access to ransomware screen"""
    files = DemoFile.query.all()
    bitcoin_address = "1" + ''.join(random.choices('123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz', k=33))
    ransom_amount = random.choice([1.0, 1.5, 2.0, 2.5])
    
    return render_template("ransomware_screen.html",
                         bitcoin_address=bitcoin_address,
                         ransom_amount=ransom_amount,
                         encrypted_files=files,
                         source='direct')

@app.route("/ransomware/reveal")
def ransomware_reveal():
    """Educational reveal page"""
    # Restore files
    files = DemoFile.query.all()
    for f in files:
        f.status = "available"
        f.remark = "Restored after simulation"
    
    db.session.commit()
    
    return render_template("ransomware_education.html")

# PHISHING ROUTES

@app.route('/product/<int:product_id>')
def product(product_id):
    """Product page - PHISHING STAGE 1"""
    product = Product.query.get_or_404(product_id)
    
    # Track Stage 1: Viewed product
    funnel = PhishingFunnel(
        session_id=session.get('session_id'),
        stage='marketplace',
        details=f"Viewed product: {product.name}"
    )
    db.session.add(funnel)
    db.session.commit()
    
    return render_template("product.html", product=product)

@app.route("/page/<slug>")
def page(slug):
    # Mock page content
    mock_pages = {
        'exotic-plants': {'title': 'Exotic Plants Market', 'content': 'Coming soon...'},
        'rare-specimens': {'title': 'Rare Plant Specimens', 'content': 'Coming soon...'},
        'tactical-gear': {'title': 'Tactical Equipment Market', 'content': 'Coming soon...'},
        'military-surplus': {'title': 'Military Equipment Market', 'content': 'Coming soon...'},
        'weapon-collect': {'title': 'Weapons Collection Market', 'content': 'Coming soon...'}
    }
    
    page = mock_pages.get(slug)
    if page is None:
        return render_template('404.html'), 404
    return render_template('page.html', page=page)

@app.route("/phishing/consent")
def phishing_consent():
    return render_template("phishing_consent.html")

@app.route("/phishing/login", methods=["GET", "POST"])
def phishing_login():
    product_id = request.args.get('product_id')
    product = None
    if product_id:
        product = Product.query.get(product_id)
    
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        
        # Track Stage 3: Entered credentials
        funnel = PhishingFunnel(
            session_id=session.get('session_id'),
            stage='credentials',
            details=f"Submitted credentials - Username: {username}"
        )
        db.session.add(funnel)
        
        cred = SimulatedCredential(
            username=username[:255],
            password=password,
            note=f"Purchase simulation for product {product_id if product_id else 'unknown'}"
        )
        
        db.session.add(cred)
        db.session.commit()
        
        # Calculate phishing metrics
        total_phished = SimulatedCredential.query.count()
        yesterday = datetime.utcnow() - timedelta(days=1)
        recent_phished = SimulatedCredential.query.filter(
            SimulatedCredential.timestamp >= yesterday
        ).count()
        unique_victims = db.session.query(SimulatedCredential.username).distinct().count()
        
        metrics = {
            'total_phished': total_phished,
            'recent_phished': recent_phished,
            'unique_victims': unique_victims,
            'your_number': total_phished
        }
        
        # Redirect to payment page if product exists
        if product:
            return redirect(url_for('payment', product_id=product_id))
        return render_template("phishing_result.html",
                             username=username,
                             product=product,
                             metrics=metrics)
    
    return render_template("phishing_login.html", product=product)

@app.route("/payment/<product_id>")
def payment(product_id):
    """Payment page - PHISHING STAGE 2"""
    product = Product.query.get_or_404(product_id)
    
    # Track Stage 2: Reached payment page
    funnel = PhishingFunnel(
        session_id=session.get('session_id'),
        stage='payment',
        details=f"Reached payment for: {product.name}"
    )
    db.session.add(funnel)
    db.session.commit()
    
    return render_template("payment.html", product=product)

@app.route("/process_payment/<product_id>", methods=["POST"])
def process_payment(product_id):
    product = Product.query.get_or_404(product_id)
    
    # Get the username from the most recent credential submission
    latest_cred = SimulatedCredential.query.order_by(SimulatedCredential.timestamp.desc()).first()
    username = latest_cred.username if latest_cred else "Unknown"
    
    # Calculate phishing metrics
    total_phished = SimulatedCredential.query.count()
    yesterday = datetime.utcnow() - timedelta(days=1)
    recent_phished = SimulatedCredential.query.filter(
        SimulatedCredential.timestamp >= yesterday
    ).count()
    unique_victims = db.session.query(SimulatedCredential.username).distinct().count()
    
    metrics = {
        'total_phished': total_phished,
        'recent_phished': recent_phished,
        'unique_victims': unique_victims,
        'your_number': total_phished
    }
    
    # Show phishing result page with metrics
    return render_template("phishing_result.html",
                         username=username,
                         product=product,
                         metrics=metrics)

# DASHBOARD WITH FUNNEL METRICS

@app.route("/dashboard")
def dashboard():
    # Phishing Funnel Metrics
    phish_stage1 = db.session.query(PhishingFunnel.session_id).filter(
        PhishingFunnel.stage == 'marketplace'
    ).distinct().count()
    
    phish_stage2 = db.session.query(PhishingFunnel.session_id).filter(
        PhishingFunnel.stage == 'payment'
    ).distinct().count()
    
    phish_stage3 = db.session.query(PhishingFunnel.session_id).filter(
        PhishingFunnel.stage == 'credentials'
    ).distinct().count()
    
    # Ransomware Funnel Metrics
    ransom_stage1 = db.session.query(RansomwareFunnel.session_id).filter(
        RansomwareFunnel.stage == 'menu'
    ).distinct().count()
    
    ransom_stage2 = db.session.query(RansomwareFunnel.session_id).filter(
        RansomwareFunnel.stage == 'interaction'
    ).distinct().count()
    
    ransom_stage3 = db.session.query(RansomwareFunnel.session_id).filter(
        RansomwareFunnel.stage == 'triggered'
    ).distinct().count()
    
    # Calculate conversion rates
    phish_conv_1_2 = (phish_stage2 / phish_stage1 * 100) if phish_stage1 > 0 else 0
    phish_conv_2_3 = (phish_stage3 / phish_stage2 * 100) if phish_stage2 > 0 else 0
    phish_conv_total = (phish_stage3 / phish_stage1 * 100) if phish_stage1 > 0 else 0
    
    ransom_conv_1_2 = (ransom_stage2 / ransom_stage1 * 100) if ransom_stage1 > 0 else 0
    ransom_conv_2_3 = (ransom_stage3 / ransom_stage2 * 100) if ransom_stage2 > 0 else 0
    ransom_conv_total = (ransom_stage3 / ransom_stage1 * 100) if ransom_stage1 > 0 else 0
    
    # Recent activity
    recent_phish = PhishingFunnel.query.order_by(PhishingFunnel.timestamp.desc()).limit(15).all()
    recent_ransom = RansomwareFunnel.query.order_by(RansomwareFunnel.timestamp.desc()).limit(15).all()
    
    # All credentials captured
    all_creds = SimulatedCredential.query.order_by(SimulatedCredential.timestamp.desc()).all()
    
    metrics = {
        'phishing': {
            'stage1': phish_stage1,
            'stage2': phish_stage2,
            'stage3': phish_stage3,
            'conv_1_2': phish_conv_1_2,
            'conv_2_3': phish_conv_2_3,
            'conv_total': phish_conv_total
        },
        'ransomware': {
            'stage1': ransom_stage1,
            'stage2': ransom_stage2,
            'stage3': ransom_stage3,
            'conv_1_2': ransom_conv_1_2,
            'conv_2_3': ransom_conv_2_3,
            'conv_total': ransom_conv_total
        }
    }
    
    return render_template("dashboard.html",
                         metrics=metrics,
                         recent_phish=recent_phish,
                         recent_ransom=recent_ransom,
                         all_creds=all_creds)

# OTHER ROUTES

@app.route("/ransomware/simulate", methods=["POST"])
def ransomware_simulate():
    files = DemoFile.query.all()
    for f in files:
        f.status = "encrypted"
        f.remark = "Marked encrypted for demo. No real file operations performed."
    db.session.commit()
    flash("Ransomware simulation executed on demo items (NO REAL FILES TOUCHED).", "info")
    return redirect(url_for("dashboard"))

@app.route("/ransomware/restore", methods=["POST"])
def ransomware_restore():
    files = DemoFile.query.all()
    for f in files:
        f.status = "available"
        f.remark = "Restored in simulation."
    db.session.commit()
    flash("Demo files restored (simulation).", "success")
    return redirect(url_for("dashboard"))

@app.route("/api/logs")
def api_logs():
    creds = SimulatedCredential.query.order_by(SimulatedCredential.timestamp.desc()).limit(200).all()
    data = [{"id": c.id, "username": c.username, "note": c.note, "ts": c.timestamp.isoformat()} for c in creds]
    return jsonify(data)

@app.route("/deets")
def deets():
    # This route is not linked anywhere — only accessible by typing /deets manually.
    creds = SimulatedCredential.query.order_by(SimulatedCredential.id.desc()).all()
    files = DemoFile.query.order_by(DemoFile.id.desc()).all()
    products = Product.query.order_by(Product.id.desc()).all()
    return render_template("deets.html", creds=creds, files=files, products=products)

@app.route('/resources')
def resources():
    return render_template('resources.html')

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
