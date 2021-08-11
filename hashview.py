from hashview import create_app 

app = create_app()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=443, ssl_context=('./hashview/ssl/cert.pem', './hashview/ssl/key.pem'), debug=True)