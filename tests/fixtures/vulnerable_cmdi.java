// Уязвимость CWE-78: пользовательский ввод передаётся напрямую в Runtime.exec
public String runCommand(String userInput) throws Exception {
    Process p = Runtime.getRuntime().exec("ls " + userInput);
    return new String(p.getInputStream().readAllBytes());
}