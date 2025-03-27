import os
from app import create_app  # importando a factory do Flask corretamente

# Instancia o aplicativo Flask usando a factory definida no __init__.py
app = create_app()

# Execução do Flask App
if __name__ == "__main__":
    debug_mode = os.getenv("FLASK_DEBUG", "False").lower() in ["true", "1"]
    port = int(os.getenv("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=debug_mode)
