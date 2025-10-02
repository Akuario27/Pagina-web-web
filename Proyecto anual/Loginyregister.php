<?php

$host = "localhost";
$user = "root";
$pass = "";
$db   = "mi_basedatos"; // cambia al nombre real de tu BD

$conn = new mysqli($host, $user, $pass, $db);
if ($conn->connect_error) die("Error de conexión: " . $conn->connect_error);

session_start();

function limpiar($s){ return trim(filter_var($s, FILTER_SANITIZE_STRING)); }

$ok = null; $errores = [];
$accion = $_POST['accion'] ?? '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

   
    if ($accion === "register") {
        $email = filter_var($_POST['email'] ?? '', FILTER_VALIDATE_EMAIL);
        $nombre = limpiar($_POST['nombre'] ?? '');
        $apellido = limpiar($_POST['apellido'] ?? '');
        $pass = $_POST['password'] ?? '';

        if (!$email)           $errores[] = "Correo inválido.";
        if ($nombre === '')    $errores[] = "Nombre requerido.";
        if ($apellido === '')  $errores[] = "Apellido requerido.";
        if (!preg_match('/^(?=.*[A-Z])(?=.*\d).{8,}$/', $pass))
            $errores[] = "Contraseña: min 8 caracteres, 1 mayúscula y 1 número.";

       
        if ($email) {
            $stmt = $conn->prepare("SELECT id FROM usuarios WHERE email=? LIMIT 1");
            $stmt->bind_param("s", $email);
            $stmt->execute();
            $stmt->store_result();
            if ($stmt->num_rows > 0) $errores[] = "Ese correo ya está registrado.";
            $stmt->close();
        }

        if (!$errores) {
            $hash = password_hash($pass, PASSWORD_DEFAULT);
            $stmt = $conn->prepare("INSERT INTO usuarios (email,nombre,apellido,password) VALUES (?,?,?,?)");
            $stmt->bind_param("ssss", $email, $nombre, $apellido, $hash);
            if ($stmt->execute()) {
                $ok = "¡Registrado con éxito! Ahora inicia sesión.";
            } else {
                $errores[] = "Error al guardar: " . $conn->error;
            }
            $stmt->close();
        }
    }

    
    if ($accion === "login") {
        $email = filter_var($_POST['email'] ?? '', FILTER_VALIDATE_EMAIL);
        $pass  = $_POST['password'] ?? '';

        if (!$email || !$pass) {
            $errores[] = "Completa todos los campos.";
        } else {
            $stmt = $conn->prepare("SELECT id, nombre, apellido, password FROM usuarios WHERE email=? LIMIT 1");
            $stmt->bind_param("s", $email);
            $stmt->execute();
            $stmt->store_result();
            if ($stmt->num_rows === 1) {
                $stmt->bind_result($id,$nom,$ape,$hash);
                $stmt->fetch();
                if (password_verify($pass, $hash)) {
                    $_SESSION['user'] = "$nom $ape";
                    $ok = "Bienvenido, $nom $ape";
                } else {
                    $errores[] = "Contraseña incorrecta.";
                }
            } else {
                $errores[] = "No existe una cuenta con ese correo.";
            }
            $stmt->close();
        }
    }
}
?>
<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<title>Auth Demo</title>
<style>
body{font-family:system-ui,Roboto,Arial;margin:2rem;background:#f6f7f9}
form{max-width:420px;margin:auto;background:#fff;padding:1.25rem;border-radius:12px;box-shadow:0 6px 18px rgba(0,0,0,.08)}
input,button{width:100%;padding:.7rem;margin:.35rem 0 1rem;border-radius:10px;border:1px solid #ccc}
button{background:#0d6efd;color:#fff;font-weight:600;border:none;cursor:pointer}
.alert{max-width:420px;margin:0 auto 1rem;padding:.8rem;border-radius:10px}
.ok{background:#e8f6ee;border:1px solid #b9e6c7}
.err{background:#fde8e8;border:1px solid #f5c2c2}
h2{text-align:center}
</style>
</head>
<body>

<?php if ($ok): ?>
<div class="alert ok"><?=htmlspecialchars($ok)?></div>
<?php endif; ?>

<?php if ($errores): ?>
<div class="alert err">
    <?php foreach($errores as $e) echo "<div>".htmlspecialchars($e)."</div>"; ?>
</div>
<?php endif; ?>

<?php if (!isset($_SESSION['user'])): ?>
<form method="post">
    <h2>Registro</h2>
    <input type="hidden" name="accion" value="register">
    <input type="email" name="email" placeholder="Correo" required>
    <input type="text" name="nombre" placeholder="Nombre" required>
    <input type="text" name="apellido" placeholder="Apellido" required>
    <input type="password" name="password" placeholder="Contraseña segura" required>
    <button type="submit">Registrarme</button>
</form>

<form method="post">
    <h2>Login</h2>
    <input type="hidden" name="accion" value="login">
    <input type="email" name="email" placeholder="Correo" required>
    <input type="password" name="password" placeholder="Contraseña" required>
    <button type="submit">Ingresar</button>
</form>
<?php else: ?>
<div class="alert ok">Sesión activa: <?=htmlspecialchars($_SESSION['user'])?></div>
<form method="post">
    <button type="submit" name="accion" value="logout">Cerrar sesión</button>
</form>
<?php endif; ?>

   <style>
    /* === RESET Y FUENTE === */
* {
  margin: 0;
  padding: 0;
  box-sizing: border-box;
  font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif;
}

body {
  display: flex;
  flex-direction: column;
  justify-content: center;
  align-items: center;
  min-height: 100vh;
  background: linear-gradient(135deg, #1e3c72, #2a5298);
  color: #fff;
  padding: 1rem;
}

/* === FORMULARIOS === */
form {
  max-width: 380px;
  width: 100%;
  margin: 1rem auto;
  background: rgba(255, 255, 255, 0.08);
  backdrop-filter: blur(12px);
  padding: 1.8rem;
  border-radius: 20px;
  box-shadow: 0 8px 25px rgba(0, 0, 0, 0.25);
  animation: fadeIn 0.6s ease-in-out;
}

/* TITULOS */
h2 {
  text-align: center;
  margin-bottom: 1.2rem;
  font-size: 1.6rem;
  color: #fff;
  letter-spacing: 1px;
}

/* === INPUTS === */
input {
  width: 100%;
  padding: 0.9rem;
  margin: 0.4rem 0 1rem;
  border-radius: 12px;
  border: none;
  outline: none;
  background: rgba(255, 255, 255, 0.15);
  color: #fff;
  font-size: 1rem;
  transition: all 0.3s ease;
}

input::placeholder {
  color: #ddd;
}

input:focus {
  background: rgba(255, 255, 255, 0.25);
  box-shadow: 0 0 0 2px #4facfe;
}

/* === BOTONES === */
button {
  width: 100%;
  padding: 0.9rem;
  border: none;
  border-radius: 12px;
  background: linear-gradient(135deg, #4facfe, #00f2fe);
  color: #fff;
  font-weight: bold;
  cursor: pointer;
  font-size: 1rem;
  transition: transform 0.2s, box-shadow 0.2s;
}

button:hover {
  transform: scale(1.05);
  box-shadow: 0 6px 15px rgba(0, 242, 254, 0.4);
}

/* === ALERTAS === */
.alert {
  max-width: 420px;
  width: 100%;
  margin: 0.6rem auto;
  padding: 0.9rem;
  border-radius: 12px;
  font-size: 0.95rem;
}

.ok {
  background: rgba(50, 205, 50, 0.2);
  border: 1px solid #2ecc71;
  color: #dfffe3;
}

.err {
  background: rgba(255, 0, 0, 0.2);
  border: 1px solid #e74c3c;
  color: #ffe5e5;
}

/* === ANIMACIÓN === */
@keyframes fadeIn {
  from { opacity: 0; transform: translateY(-20px); }
  to   { opacity: 1; transform: translateY(0); }
}

/* === RESPONSIVE === */
@media (max-width: 480px) {
  form {
    padding: 1.2rem;
    border-radius: 15px;
  }

  h2 {
    font-size: 1.3rem;
  }
}
</body>
</html>

