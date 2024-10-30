from flask import Flask, render_template, request, redirect, session, flash, send_from_directory
import os
from flask_mysqldb import MySQL
from functools import wraps
from datetime import datetime

app = Flask(__name__)


app.secret_key = 'Toor' 

# Configuración de la conexión a la base de datos
mysql = MySQL()
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'proyectowebflask'
app.config['MYSQL_PORT'] = 3306
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

mysql.init_app(app)

# Ruta para servir imágenes desde la carpeta resources
@app.route('/resources/<path:filename>')
def resources(filename):
    return send_from_directory('resources', filename)

# Context Processor para pasar información del usuario a todas las plantillas
@app.context_processor
def inject_user():
    user = None
    if 'id_usuario' in session:
        try:
            conexion = mysql.connection
            cursor = conexion.cursor()
            sql_user = "SELECT Username, role_id FROM usuarios WHERE ID=%s"
            cursor.execute(sql_user, (session['id_usuario'],))
            user = cursor.fetchone()
            conexion.commit()
        except Exception as e:
            print(f"Error fetching user data: {e}")
            user = None
    return dict(current_user=user)

# Decorador para requerir login en ciertas rutas
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'id_usuario' not in session:
            flash('Por favor, inicie sesión para acceder a esta página.', 'warning')
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated_function

# Decorador para requerir un rol específico
def role_required(role_id):
    def wrapper(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'id_usuario' not in session:
                flash('Por favor, inicie sesión para acceder a esta página.', 'warning')
                return redirect('/login')
            # Verificar si el usuario tiene el rol adecuado
            sql = "SELECT role_id FROM usuarios WHERE ID=%s"
            conexion = mysql.connection
            cursor = conexion.cursor()
            cursor.execute(sql, (session['id_usuario'],))
            usuario = cursor.fetchone()
            conexion.commit()

            if usuario is None or usuario['role_id'] != role_id:
                flash('No tienes permiso para acceder a esta página.', 'danger')
                return redirect('/')
            return f(*args, **kwargs)
        return decorated_function
    return wrapper

# Ruta principal
@app.route('/')
def home():
    return render_template('sitio/index.html')

# -------------------- Rutas de Autenticación --------------------

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        Username = request.form['Username']
        Cedula = request.form['Cedula']
        Numero = request.form['Numero']
        Password = request.form['Password']
        role_id = 4 

        try:
            conexion = mysql.connection
            cursor = conexion.cursor()
            sql = "INSERT INTO usuarios (Username, Password, Numero, Cedula, role_id) VALUES (%s, %s, %s, %s, %s)"
            datos = (Username, Password, Numero, Cedula, role_id)
            cursor.execute(sql, datos)
            conexion.commit()
            flash('Usuario registrado exitosamente.', 'success')
            return redirect('/login')
        except Exception as e:
            print(f"Error registrando usuario: {e}")
            flash('Ocurrió un error al registrar el usuario.', 'danger')
            return redirect('/register')
    return render_template('sitio/register.html')


# Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        Username = request.form['Username']
        Password = request.form['Password']
        
        # Consultar al usuario en la base de datos
        sql = "SELECT * FROM usuarios WHERE Username=%s AND Password=%s"
        conexion = mysql.connection
        cursor = conexion.cursor()
        cursor.execute(sql, (Username, Password))
        user = cursor.fetchone()
        conexion.commit()
        
        if user:
            session['id_usuario'] = user['ID']
            flash('Inicio de sesión exitoso!', 'success')
            return redirect('/')
        else:
            flash('Credenciales Inválidas. Inténtalo Nuevamente.', 'danger')
            return redirect('/login')
    return render_template('sitio/login.html')

# Logout
@app.route('/logout')
@login_required
def logout():
    session.pop('id_usuario', None)
    flash('Has cerrado sesión exitosamente.', 'success')
    return redirect('/')

# -------------------- Rutas de Usuarios --------------------

# Usuarios - Listar
@app.route('/sitio/Usuarios')
@login_required
@role_required(1)
def admin_usuarios():
    sql = "SELECT * FROM usuarios"
    conexion = mysql.connection
    cursor = conexion.cursor()
    cursor.execute(sql)
    usuarios = cursor.fetchall()
    conexion.commit()
    return render_template('sitio/Usuarios.html', usuarios=usuarios)

# Guardar Usuario
@app.route('/sitio/guardarU', methods=['POST'])
@login_required
@role_required(1)
def guardarU():
    Username = request.form['Username']
    Password = request.form['Password']
    Numero = request.form['Numero']
    Cedula = request.form['Cedula']  # Añadir la variable Cedula
    role_id = 4  # Asignar role fijo a usuarios nuevos

    # Incluir la columna Cedula en el comando INSERT
    sql = "INSERT INTO usuarios (Username, Password, Numero, Cedula, role_id) VALUES (%s, %s, %s, %s, %s)"
    datos = (Username, Password, Numero, Cedula, role_id)
    
    conexion = mysql.connection
    cursor = conexion.cursor()
    cursor.execute(sql, datos)
    conexion.commit()
    flash('Usuario guardado exitosamente con role_id=4.', 'success')
    return redirect('/sitio/Usuarios')

# Borrar Usuario
@app.route('/sitio/borrarU/<int:id>')
@login_required
@role_required(1)
def borrarU(id):
    sql ="DELETE FROM usuarios WHERE ID=%s"
    conexion = mysql.connection
    cursor = conexion.cursor()
    cursor.execute(sql, (id,))
    conexion.commit()
    flash('Usuario borrado exitosamente.', 'success')
    return redirect('/sitio/Usuarios')

# Editar Usuario
@app.route('/sitio/editarU/<int:id>')
@login_required
@role_required(1)
def editarU(id):
    sql = "SELECT * FROM usuarios WHERE ID=%s"
    conexion = mysql.connection
    cursor = conexion.cursor()
    cursor.execute(sql, (id,))
    usuario = cursor.fetchone()
    conexion.commit()
    return render_template('/sitio/editarU.html', usuario=usuario)

# Actualizar Usuario
@app.route('/sitio/actualizarU', methods=['POST'])
@login_required
@role_required(1)
def actualizarU():
    Username = request.form['Username']
    Password = request.form['Password']
    Numero = request.form['Numero']
    Cedula = request.form['Cedula']
    ID = request.form['ID']
    sql = "UPDATE usuarios SET Username=%s, Password=%s, Numero=%s, Cedula=%s WHERE ID=%s"
    datos = (Username, Password, Numero, Cedula, ID)
    conexion = mysql.connection
    cursor = conexion.cursor()
    cursor.execute(sql, datos)
    conexion.commit()
    flash('Usuario actualizado exitosamente.', 'success')
    return redirect('/sitio/Usuarios')

# -------------------- Rutas de Citas --------------------

# Ruta para visualizar el calendario de citas y agendar nuevas
@app.route('/sitio/citas')
@login_required
def citas():
    try:
        conexion = mysql.connection
        cursor = conexion.cursor()
        # Obtener todas las citas existentes para el calendario
        sql_todas_citas = "SELECT fecha, hora FROM citas"
        cursor.execute(sql_todas_citas)
        citas_existentes = cursor.fetchall()
        
        # Obtener las citas del usuario actual
        usuario_id = session['id_usuario']
        sql_usuario_citas = "SELECT fecha, hora FROM citas WHERE usuario_id=%s"
        cursor.execute(sql_usuario_citas, (usuario_id,))
        citas_usuario = cursor.fetchall()
        
        conexion.commit()
        
        # Asegurarse de que las fechas y horas son objetos datetime
        for cita in citas_existentes:
            if not isinstance(cita['fecha'], datetime):
                cita['fecha'] = datetime.strptime(str(cita['fecha']), '%Y-%m-%d')
            if not isinstance(cita['hora'], datetime):
                cita['hora'] = datetime.strptime(str(cita['hora']), '%H:%M:%S')
                
        for cita in citas_usuario:
            if not isinstance(cita['fecha'], datetime):
                cita['fecha'] = datetime.strptime(str(cita['fecha']), '%Y-%m-%d')
            if not isinstance(cita['hora'], datetime):
                cita['hora'] = datetime.strptime(str(cita['hora']), '%H:%M:%S')
        
        return render_template('sitio/citas.html', citas=citas_existentes, citas_usuario=citas_usuario)
    except Exception as e:
        print(f"Error al obtener las citas: {e}")
        flash('Ocurrió un error al cargar las citas.', 'danger')
        return redirect('/')

# Ruta para manejar el formulario de agendar cita
@app.route('/sitio/agendar_cita', methods=['POST'])
@login_required
def agendar_cita():
    fecha = request.form['fecha']
    hora = request.form['hora']
    usuario_id = session['id_usuario']

    # Validar que la fecha y hora no estén ya ocupadas
    try:
        conexion = mysql.connection
        cursor = conexion.cursor()
        sql_verificar = "SELECT * FROM citas WHERE fecha=%s AND hora=%s"
        cursor.execute(sql_verificar, (fecha, hora))
        cita_existente = cursor.fetchone()
        if cita_existente:
            flash('El horario seleccionado ya está ocupado. Por favor, elige otro.', 'danger')
            return redirect('/sitio/citas')
        
        # Insertar la nueva cita
        sql_insert = "INSERT INTO citas (fecha, hora, usuario_id) VALUES (%s, %s, %s)"
        cursor.execute(sql_insert, (fecha, hora, usuario_id))
        conexion.commit()
        flash('Cita agendada exitosamente.', 'success')
        return redirect('/sitio/citas')
    except Exception as e:
        print(f"Error al agendar la cita: {e}")
        flash('Ocurrió un error al agendar la cita.', 'danger')
        return redirect('/sitio/citas')

# Ruta para cancelar una cita (solo del usuario actual)
@app.route('/sitio/cancelar_cita/<fecha>/<hora>')
@login_required
def cancelar_cita(fecha, hora):
    usuario_id = session['id_usuario']
    try:
        conexion = mysql.connection
        cursor = conexion.cursor()
        sql = "DELETE FROM citas WHERE fecha=%s AND hora=%s AND usuario_id=%s"
        cursor.execute(sql, (fecha, hora, usuario_id))
        conexion.commit()
        if cursor.rowcount > 0:
            flash('Cita cancelada exitosamente.', 'success')
        else:
            flash('No se encontró la cita para cancelar.', 'warning')
        return redirect('/sitio/citas')
    except Exception as e:
        print(f"Error al cancelar la cita: {e}")
        flash('Ocurrió un error al cancelar la cita.', 'danger')
        return redirect('/sitio/citas')

# -------------------- Actualización de Rol --------------------

# Actualización de rol - Formulario
@app.route('/sitio/actualizarRol', methods=['GET'])
@login_required
@role_required(1)
def actualizarRol_form():
    roles = {
        1: 'Admin',
        2: 'Doctor',
        3: 'Asistente',
        4: 'Paciente'
    }
    
    # Obtener la lista de usuarios
    sql = "SELECT Username FROM usuarios"
    conexion = mysql.connection
    cursor = conexion.cursor()
    cursor.execute(sql)
    usuarios = cursor.fetchall()
    
    return render_template('sitio/actualizarRol.html', roles=roles, usuarios=usuarios)

# Actualización de rol
@app.route('/sitio/actualizarRol', methods=['POST'])
@login_required
@role_required(1)
def actualizarRol():
    username = request.form['Username']
    nuevo_rol = request.form['role_id']
    
    # Validar que el rol ingresado sea válido
    if int(nuevo_rol) not in [1, 2, 3, 4]:
        flash('Rol inválido seleccionado.', 'danger')
        return redirect('/sitio/actualizarRol')
    
    try:
        sql = "UPDATE usuarios SET role_id=%s WHERE Username=%s"
        datos = (nuevo_rol, username)
        conexion = mysql.connection
        cursor = conexion.cursor()
        cursor.execute(sql, datos)
        conexion.commit()
        
        if cursor.rowcount == 0:
            flash('No se encontró ningún usuario con ese nombre.', 'warning')
        else:
            flash('Rol actualizado exitosamente.', 'success')
    except Exception as e:
        print(f"Error actualizando rol: {e}")
        flash('Ocurrió un error al actualizar el rol.', 'danger')
    
    return redirect('/sitio/Usuarios')


@app.route('/sitio/diagnosticos', methods=['GET', 'POST'])
@login_required
def diagnosticos():
    try:
        conexion = mysql.connection
        cursor = conexion.cursor()

        # Obtener todas las citas con información del paciente que NO tienen diagnóstico
        sql_citas = """
            SELECT citas.id, citas.fecha, citas.hora, usuarios.Username AS nombre_paciente
            FROM citas
            JOIN usuarios ON citas.usuario_id = usuarios.ID
            LEFT JOIN diagnosticos ON citas.id = diagnosticos.cita_id
            WHERE diagnosticos.id IS NULL
        """
        cursor.execute(sql_citas)
        citas = cursor.fetchall()

        if request.method == 'POST':
            if 'diagnostico' in request.form:  # Añadido para distinguir entre agregar y eliminar
                diagnostico = request.form['diagnostico']
                cita_id = request.form['cita_id']

                # Guardar el diagnóstico en la base de datos
                sql_insert_diagnostico = "INSERT INTO diagnosticos (cita_id, diagnostico) VALUES (%s, %s)"
                cursor.execute(sql_insert_diagnostico, (cita_id, diagnostico))
                conexion.commit()

                flash('Diagnóstico agregado exitosamente.', 'success')
            elif 'eliminar_diagnostico' in request.form:  # Bloque para eliminar diagnóstico
                diagnostico_id = request.form['eliminar_diagnostico']

                # Eliminar el diagnóstico de la base de datos
                sql_delete_diagnostico = "DELETE FROM diagnosticos WHERE id = %s"
                cursor.execute(sql_delete_diagnostico, (diagnostico_id,))
                conexion.commit()

                flash('Diagnóstico eliminado exitosamente.', 'success')

            return redirect('/sitio/diagnosticos')

        # Obtener diagnósticos realizados
        sql_diagnosticos = """
            SELECT d.id, d.diagnostico, c.fecha, c.hora, u.Username AS nombre_paciente
            FROM diagnosticos d
            JOIN citas c ON d.cita_id = c.id
            JOIN usuarios u ON c.usuario_id = u.ID
        """
        cursor.execute(sql_diagnosticos)
        diagnosticos_realizados = cursor.fetchall()

        return render_template('sitio/diagnosticos.html', citas=citas, diagnosticos=diagnosticos_realizados)

    except Exception as e:
        print(f"Error al cargar diagnósticos: {e}")
        flash('Ocurrió un error al cargar los diagnósticos.', 'danger')
        return redirect('/')

@app.route('/sitio/medicamentos', methods=['GET'])
@login_required
def medicamentos():
    try:
        conexion = mysql.connection
        cursor = conexion.cursor()

        # Obtener el usuario que ha iniciado sesión
        usuario_id = session['id_usuario']

        # Filtrar los diagnósticos y medicamentos solo para el paciente conectado
        sql_medicamentos = """
            SELECT d.diagnostico, d.medicamento, c.fecha, c.hora, u.Username AS nombre_paciente, u.Numero AS numero_paciente
            FROM diagnosticos d
            JOIN citas c ON d.cita_id = c.id
            JOIN usuarios u ON c.usuario_id = u.ID
            WHERE u.ID = %s  -- Filtrar por el usuario autenticado
        """
        cursor.execute(sql_medicamentos, (usuario_id,))
        diagnosticos_medicamentos = cursor.fetchall()

        return render_template('sitio/medicamentos.html', diagnosticos=diagnosticos_medicamentos)

    except Exception as e:
        print(f"Error al cargar medicamentos: {e}")
        flash('Ocurrió un error al cargar los medicamentos.', 'danger')
        return redirect('/')
    
    
# -------------------- Ejecución de la Aplicación --------------------

if __name__ == '__main__':
    app.run(debug=True)