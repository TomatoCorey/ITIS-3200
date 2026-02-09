import java.io.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

public class Lab02HashingProgram {
    public static void main(String[] args) throws Exception {
        Scanner input = new Scanner(System.in);

        System.out.println("1 - Generate new hash table");
        System.out.println("2 - Verify hashes");
        System.out.print("Choose an option: ");

        int choice = input.nextInt();
        input.nextLine();

        if (choice == 1) {
            generateHashTable(input);
        } else if (choice == 2) {
            verifyHashes(input);
        } else {
            System.out.println("Invalid option.");
        }
    }

    private static void generateHashTable(Scanner input) throws Exception {
        System.out.print("Enter directory path: ");
        Path dir = Paths.get(input.nextLine());

        if (!Files.isDirectory(dir)) {
            System.out.println("Not a valid directory.");
            return;
        }

        Map<String, String> hashTable = new LinkedHashMap<>();

        Files.walk(dir)
                .filter(Files::isRegularFile)
                .forEach(path -> {
                    try {
                        String hash = hashFile(path);
                        hashTable.put(path.toString(), hash);
                    } catch (Exception e) {
                        System.err.println("Failed to hash: " + path);
                    }
                });

        Path output = Paths.get("hashes.json");
        writeJson(hashTable, output);

        System.out.println("Hash table saved to " + output.toAbsolutePath());
    }

    private static void writeJson(Map<String, String> map, Path output) throws IOException {
        try (BufferedWriter writer = Files.newBufferedWriter(output)) {
            writer.write("{\n");
            Iterator<Map.Entry<String, String>> it = map.entrySet().iterator();
            while (it.hasNext()) {
                Map.Entry<String, String> e = it.next();
                writer.write("  \"" + e.getKey() + "\": \"" + e.getValue() + "\"");
                if (it.hasNext())
                    writer.write(",");
                writer.write("\n");
            }
            writer.write("}\n");
        }
    }

    private static String hashFile(Path path) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");

        try (InputStream is = Files.newInputStream(path)) {
            byte[] buffer = new byte[8192];
            int read;
            while ((read = is.read(buffer)) != -1) {
                digest.update(buffer, 0, read);
            }
        }

        return bytesToHex(digest.digest());
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder hex = new StringBuilder();
        for (byte b : bytes) {
            hex.append(String.format("%02x", b));
        }
        return hex.toString();
    }

    private static void verifyHashes(Scanner input) throws Exception {
        System.out.print("Enter path to hashes.json: ");
        Path jsonPath = Paths.get(input.nextLine());

        if (!Files.exists(jsonPath)) {
            System.out.println("JSON file not found.");
            return;
        }

        Map<String, String> storedHashes = readJson(jsonPath);

        for (Map.Entry<String, String> entry : storedHashes.entrySet()) {
            Path filePath = Paths.get(entry.getKey());

            if (!Files.exists(filePath)) {
                System.out.println("MISSING: " + filePath);
                continue;
            }

            String currentHash = hashFile(filePath);
            if (currentHash.equals(entry.getValue())) {
                System.out.println("OK: " + filePath);
            } else {
                System.out.println("CHANGED: " + filePath);
            }
        }
    }

    private static Map<String, String> readJson(Path input) throws IOException {
        Map<String, String> map = new HashMap<>();

        List<String> lines = Files.readAllLines(input);
        for (String line : lines) {
            line = line.trim();
            if (line.startsWith("\"")) {
                String[] parts = line.split("\"");
                String path = parts[1];
                String hash = parts[3];
                map.put(path, hash);
            }
        }
        return map;
    }
}