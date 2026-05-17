// Fixture: уязвимости Go-приложения (HTTP сервер).
// Уровень: HIGH / MEDIUM
// CWE: CWE-78 (Command Injection), CWE-362 (Race Condition),
//      CWE-400 (Resource Exhaustion), CWE-703 (Error Handling)

package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"sync"
)

// ─────────────────────────────────────────────────────────
// CWE-78: Command Injection через exec.Command + shell (HIGH)
// exec.Command("sh", "-c", ...) с пользовательским вводом опасен.
// Payload: "; cat /etc/passwd"
// ─────────────────────────────────────────────────────────
func pingHandler(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	// УЯЗВИМОСТЬ: аргумент передаётся через shell, а не напрямую в ping
	cmd := exec.Command("sh", "-c", "ping -c 1 "+host)
	out, err := cmd.Output()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	fmt.Fprintf(w, string(out))
}

// ─────────────────────────────────────────────────────────
// CWE-362: Race Condition (TOCTOU) (HIGH)
// Проверка файла и его чтение — две отдельные операции.
// Между ними файл может быть подменён (symlink attack).
// ─────────────────────────────────────────────────────────
func readUserFile(userPath string) ([]byte, error) {
	// УЯЗВИМОСТЬ: check-then-use без атомарной операции
	if _, err := os.Stat(userPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("file not found")
	}
	// Здесь между Stat и ReadFile атакующий может подменить файл
	return ioutil.ReadFile(userPath)
}

// ─────────────────────────────────────────────────────────
// CWE-362: Data Race на общей структуре (HIGH)
// Несколько горутин пишут в map без синхронизации.
// ─────────────────────────────────────────────────────────
var sessionStore = make(map[string]string) // УЯЗВИМОСТЬ: нет мьютекса

func setSession(token, value string) {
	// УЯЗВИМОСТЬ: конкурентная запись в map → неопределённое поведение
	sessionStore[token] = value
}

func getSession(token string) string {
	// УЯЗВИМОСТЬ: конкурентное чтение/запись → паника в рантайме
	return sessionStore[token]
}

// ─────────────────────────────────────────────────────────
// CWE-400: Неограниченное потребление ресурсов (MEDIUM)
// Клиент может создать сколько угодно горутин, DoS-атака.
// ─────────────────────────────────────────────────────────
func processRequestsHandler(w http.ResponseWriter, r *http.Request) {
	count := r.URL.Query().Get("count") // может быть "1000000"
	n := 0
	fmt.Sscanf(count, "%d", &n)

	var wg sync.WaitGroup
	// УЯЗВИМОСТЬ: нет ограничения на n — можно запустить миллион горутин
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// имитация работы
		}()
	}
	wg.Wait()
	fmt.Fprintf(w, "Done %d tasks", n)
}

func main() {
	http.HandleFunc("/ping", pingHandler)
	http.HandleFunc("/process", processRequestsHandler)
	http.ListenAndServe(":8080", nil)
}