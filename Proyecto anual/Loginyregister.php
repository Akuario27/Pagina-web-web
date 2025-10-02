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

</body>
</html>
