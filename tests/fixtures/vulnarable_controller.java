/**
 * Fixture: уязвимости Java-приложения (Spring Boot / Servlet).
 * Уровень: CRITICAL / HIGH
 * CWE: CWE-89 (SQL Injection), CWE-611 (XXE),
 *      CWE-502 (Unsafe Deserialization), CWE-209 (Info Exposure)
 */

import java.io.*;
import java.sql.*;
import javax.xml.parsers.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.*;

@RestController
@RequestMapping("/api")
public class UserController {

    private Connection dbConnection;

    // ───────────────────────────────────────────────────────
    // CWE-89: SQL Injection (CRITICAL)
    // Statement вместо PreparedStatement — классическая ошибка Java.
    // ───────────────────────────────────────────────────────
    @GetMapping("/user")
    public String getUserById(@RequestParam String id) throws SQLException {
        Statement stmt = dbConnection.createStatement();
        // УЯЗВИМОСТЬ: конкатенация параметра запроса в SQL
        String query = "SELECT * FROM users WHERE id = " + id;
        ResultSet rs = stmt.executeQuery(query);
        if (rs.next()) {
            return rs.getString("username");
        }
        return "Not found";
    }

    // ───────────────────────────────────────────────────────
    // CWE-611: XML External Entity (XXE) (HIGH)
    // Атака позволяет читать файлы сервера через XML-сущности.
    // Payload: <!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
    // ───────────────────────────────────────────────────────
    @PostMapping("/parse-xml")
    public ResponseEntity<String> parseXml(@RequestBody String xmlBody) {
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            // УЯЗВИМОСТЬ: внешние сущности не отключены (должны быть setFeature)
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document doc = builder.parse(
                new ByteArrayInputStream(xmlBody.getBytes())
            );
            return ResponseEntity.ok("Parsed OK");
        } catch (Exception e) {
            // УЯЗВИМОСТЬ (CWE-209): стек-трейс возвращается пользователю
            return ResponseEntity.status(500).body(e.toString());
        }
    }

    // ───────────────────────────────────────────────────────
    // CWE-502: Небезопасная десериализация Java (CRITICAL)
    // ObjectInputStream.readObject() — вектор для RCE через gadget chains
    // (Apache Commons Collections, Spring Framework и др.)
    // ───────────────────────────────────────────────────────
    @PostMapping("/load-object")
    public ResponseEntity<String> loadObject(@RequestBody byte[] data) {
        try {
            // УЯЗВИМОСТЬ: десериализация произвольных байт от клиента
            ObjectInputStream ois = new ObjectInputStream(
                new ByteArrayInputStream(data)
            );
            Object obj = ois.readObject();
            return ResponseEntity.ok(obj.toString());
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error: " + e.getMessage());
        }
    }

    // ───────────────────────────────────────────────────────
    // CWE-209: Раскрытие стек-трейса (MEDIUM)
    // Информация об архитектуре сервера помогает атакующему.
    // ───────────────────────────────────────────────────────
    @GetMapping("/data")
    public ResponseEntity<String> getData(@RequestParam String query) {
        try {
            String result = processQuery(query);
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            // УЯЗВИМОСТЬ: полный стек-трейс отдаётся пользователю
            StringWriter sw = new StringWriter();
            e.printStackTrace(new PrintWriter(sw));
            return ResponseEntity.status(500).body(sw.toString());
        }
    }

    private String processQuery(String q) {
        throw new RuntimeException("Not implemented: " + q);
    }
}