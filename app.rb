require 'sinatra'
require 'slim'
require 'sqlite3'
require 'bcrypt'

enable :sessions

get('/')do
  db = SQLite3::Database.new("db/chatt.db")
  slim(:index)
end 

def set_error(error_message)
    session[:error] = error_message
    slim(:error)
end

def connect_to_db(path)
    db = SQLite3::Database.new("db/chatt.db")
    db.results_as_hash = true
    return db
end
   

get('/error')do
  slim(:error)
end

post('/register') do
    session.clear
    db = SQLite3::Database.new("db/chatt.db")
    db.results_as_hash = true
    username= params["username"]
    password= params["password"]
    password_confirmation =params["password_confirmation"]
    result = db.execute("SELECT id FROM users WHERE username=?", [username])
    
    p result
    if result.empty?
        if password == password_confirmation
            password_digest = BCrypt::Password.create(password)
            p password_digest
            db.execute("INSERT INTO users(username, password_digest) VALUES(?,?)", [username, password_digest])
            session[:user_id] = db.execute('SELECT id FROM users WHERE username = ?', username).first['id']
            redirect('/reg_confirm')
        else
            p 2
            set_error("PASS DONT MATCH MAAN")
            redirect('/error')
        end
    else
        p 1
        
set_error("username already exist")
        redirect('/error')
    end
end

post('/login') do
  db = SQLite3::Database.new("db/chatt.db")
  db.results_as_hash = true
  username= params["username"]
  password= params["password"]
  result = db.execute("SELECT id, password_digest, admin FROM users WHERE username=?", [username])
  if result.empty?
    set_error("Något gick fel, försök igen")
    redirect('/error')
  end

  if session[:attempt].nil?
    session[:attempt] = Time.now
elsif Time.now - session[:attempt] < 20 
    session[:error] = "Du har slagit in fel lösenord, försök igen om en stund"
    redirect('/error')
end 

session[:attempt] = Time.now


  user_id = result.first["id"]
  password_digest = result.first["password_digest"]
  if BCrypt::Password.new(password_digest)==password
      session[:user_id] = user_id
      if result.first["admin"].to_s == '1'
        admin = true
      else
        admin = false
      end
      session[:admin] = admin
  else
    # Wrong password
      redirect '/'
  end
  # Correct password and successfully signed in
  redirect '/reg_confirm'
end

get '/admin/*' do
    if session[:admin] == true
      # It´s an admin
    else
      # Not a admin
        redirect '/'
    end

    slim :admin
end



get('/reg_confirm') do
    user_id = session[:user_id]
    db = SQLite3::Database.new("db/chatt.db")
    db.results_as_hash = true
    search = session[:search]
    result = db.execute("SELECT * FROM users WHERE username LIKE ?", '%'+search.to_s+'%')
    admin = session[:admin]
    p result
    slim(:"lists/index1",locals:{chatt:result, admin: admin})
end

post('/search_user') do
    db = SQLite3::Database.new("db/chatt.db")
    db.results_as_hash = true
    search = params['username']
    p search
    session[:search] = search
    redirect('/reg_confirm')
end

get('/:id/chat') do
    db = SQLite3::Database.new("db/chatt.db")
    db.results_as_hash = true
    @admin=session['admin']
    reciever_id = params['id']
    user_id = session[:user_id]
    result = db.execute("SELECT * FROM messages WHERE reciever_id = ? AND sender_id = ? OR reciever_id = ? AND sender_id = ?", [reciever_id, user_id,  user_id, reciever_id])
    p result
    result = [] unless result.length >= 1
    slim(:"lists/chat",locals:{reciever_id:reciever_id, result:result})
end

post('/:id/chat') do
    db = SQLite3::Database.new("db/chatt.db")
    db.results_as_hash = true
    message = params['message']
    reciever_id = params['id']
    p session[:user_id]
    sender_id = session[:user_id]
    timestamp = Time.now.to_s
    db.execute("INSERT INTO messages(sender_id, reciever_id, content, timestamp) VALUES(?,?,?,?)", [sender_id, reciever_id, message, timestamp])
    redirect("/#{reciever_id}/chat")
end

post('/:id/delete') do
  db = SQLite3::Database.new("db/chatt.db")
  db.results_as_hash = true
  id = params['id']
  db.execute('DELETE FROM users WHERE id=?', [id])
  redirect '/reg_confirm'
end

get('/group') do
  db = SQLite3::Database.new("db/chatt.db")
  db.results_as_hash = true
  user_id = session[:user_id]
  search = session[:search]
  result = db.execute("SELECT * FROM users WHERE username LIKE ?", '%'+search.to_s+'%')
  p result
  slim(:group)
end