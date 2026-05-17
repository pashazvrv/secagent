// Уязвимость CWE-22: путь к файлу формируется из пользовательского ввода без валидации
func readFile(filename string) ([]byte, error) {
    path := "/var/data/" + filename
    return os.ReadFile(path)  // атакующий может передать "../etc/passwd"
}
