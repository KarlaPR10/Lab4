Lab4-security

Scenarios for Security Design:
Scenario 1: Pseudo-Code for Authentication System

    Pseudo-Code Example

      FUNCTION authenticateUser(username, password):
        QUERY database WITH username AND password
        IF found RETURN True
        ELSE RETURN False
  
 Detalle de vulnerabilidad en SQL Injection ya que es un SQL plano tiene la puerta abierta para un ataque. contemplar que las contraseñas son temas de mucha seguridad.

Sugerencia de Solución:


    public boolean login(String usuario, String contraseña) {
        Connection conn = null;
        try {
            conn = DriverManager.getConnection("jdbc:jdbc://localhost:3306/dbname", "username", "password");
            PreparedStatement stmt = conn.prepareStatement("SELECT * FROM usuarios WHERE usuario = ? AND contraseña = ?");
            stmt.setString(1, usuario);
            stmt.setString(2, contraseña);
            ResultSet resultado = stmt.executeQuery();
            if (resultado.next()) {
                return true;
            } else {
                return false;
            }
        } catch (SQLException e) {
            return false;
        } finally {
            if (conn != null) {
                conn.close();
            }
        }
        }

Scenario 2: JWT Authentication Schema
Design Outline


    DEFINE FUNCTION generateJWT(userCredentials):
      IF validateCredentials(userCredentials):
        SET tokenExpiration = currentTime + 3600 // Token expires in one hour
        RETURN encrypt(userCredentials + tokenExpiration, secretKey)
      ELSE:
        RETURN error

Se detecto que no se encuntra un cifrado como SHA256 lo cual nos deja una vulnerabilidad y puerta abierta algun ataque.

Sugerencia de Solución:

    public Strind generateJWT(userCredentials){
    
            // Generación del token
            JwtBuilder builder = Jwts.builder()
                    .setSubject(user.getUsername().setSubject(userCredentials.get(0)))
                    .setExpiration(new Date(System.currentTimeMillis() + 3600000)) // 1 hora de expiración
                    .signWith(SignatureAlgorithm.HS256, secretKey);
            String token = builder.compact();
            // Verificación del token
            String tokenReceived = "Bearer " + token;
           return tokenReceived;
        }

Scenario 3: Secure Data Communication Plan
Outline for Data Protection:

        PLAN secureDataCommunication:
        IMPLEMENT SSL/TLS for all data in transit
        USE encrypted storage solutions for data at rest
        ENSURE all data exchanges comply with HTTPS protocols

Sugerencia 

      PLAN secureDataCommunication:
        IMPLEMENT SSL/TLS Encryption for all data in transit
        SECURE storage APIs to manage automatically encryption and decryption
        USE encrypted storage solutions for data at rest
        ENSURE all data exchanges comply with HTTPS protocols
        USE the latest version of TLS
        CONFIGURE servers to disable vulnerable protocol



        
  
