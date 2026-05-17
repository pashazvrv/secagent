// Уязвимость CWE-89: строковая конкатенация в SQL-запросе
function getUser(userId) {
    const query = "SELECT * FROM users WHERE id = " + userId;
    return db.execute(query);  // пользовательский ввод не экранируется
}