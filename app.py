# app.py - Safe Dark Web Risk Simulator (educational)
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

app = Flask(__name__)
app.secret_key = "change-this-secret-in-lab"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///simulator.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# --- Models ---
class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120))
    description = db.Column(db.Text)
    price = db.Column(db.Float)
    image = db.Column(db.String(256))

class DemoFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(256))
    status = db.Column(db.String(50), default='available')  # available / encrypted
    remark = db.Column(db.String(256), default='')

class SimulatedCredential(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(256))
    password = db.Column(db.String(256))
    note = db.Column(db.String(256))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    simulated = db.Column(db.Boolean, default=True)

def init_db():
    db.create_all()
    Product.query.delete()
    DemoFile.query.delete()
    
    # Initialize demo files for ransomware simulation
    files = [
        DemoFile(name="employee_list.csv"),
        DemoFile(name="sample_financials.xlsx"),
        DemoFile(name="project_docs.pdf")
    ]
    for file in files:
        db.session.add(file)
    
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
    
    # Mock pages for search results with improved categorization
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
        }
    ]
    
    if q:
        # Keywords for better categorization
        plant_keywords = ['plant', 'botanic', 'herb', 'crystal', 'specimen', 'extract', 'blend']
        equipment_keywords = ['equipment', 'weapon', 'tactical', 'military', 'gear', 'device']
        
        # Check if query matches category keywords
        is_plant_search = any(keyword in q for keyword in plant_keywords)
        is_equipment_search = any(keyword in q for keyword in equipment_keywords)
        
        # Define navigation links based on search category
        if is_plant_search:
            # Show only plant-related results and navigation
            results = [page for page in mock_pages if page['category'] == 'plants']
            navigation_links = [{'title': 'Plants & Botanicals', 'url': '/marketplace/plants'}]
        elif is_equipment_search:
            # Show only equipment-related results and navigation
            results = [page for page in mock_pages if page['category'] == 'equipment']
            navigation_links = [{'title': 'Equipment & Accessories', 'url': '/marketplace/weapons'}]
        else:
            # Regular search in title and content
            results = [page for page in mock_pages if q in page['title'].lower() or q in page['content'].lower()]
            # Show all navigation links if no specific category matches
            navigation_links = [
                {'title': 'Plants & Botanicals', 'url': '/marketplace/plants'},
                {'title': 'Equipment & Accessories', 'url': '/marketplace/weapons'}
            ]
    else:
        # Show all navigation links if no search query
        navigation_links = [
            {'title': 'Plants & Botanicals', 'url': '/marketplace/plants'},
            {'title': 'Equipment & Accessories', 'url': '/marketplace/weapons'}
        ]
        
    return render_template("index.html", results=results, q=q, navigation_links=navigation_links)
    
    return render_template("index.html", results=results, q=q)

@app.route("/marketplace/plants")
def marketplace_plants():
    # Include specific plant-related products
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
            Product.image.like('%m16%')
            ,
            Product.image.like('%MH12%'),
            Product.image.like('%AWM%'),
            Product.image.like('%guns1%')
        )
    ).all()
    return render_template("marketplace.html", products=products, category="Equipment & Accessories")

@app.route('/product/<int:product_id>')
def product(product_id):
    product = Product.query.get_or_404(product_id)
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
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        
        cred = SimulatedCredential(
            username=username[:255],
            password="REDACTED_IN_UI",
            note="Phishing simulation (consented)"
        )
        db.session.add(cred)
        db.session.commit()
        
        return render_template("phishing_result.html", username=username)
    
    return render_template("phishing_login.html")

@app.route("/dashboard")
def dashboard():
    creds = SimulatedCredential.query.order_by(SimulatedCredential.timestamp.desc()).limit(50).all()
    files = DemoFile.query.all()
    return render_template("dashboard.html", creds=creds, files=files)

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

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)