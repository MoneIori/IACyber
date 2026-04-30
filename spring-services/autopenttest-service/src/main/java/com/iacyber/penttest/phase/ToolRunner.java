package com.iacyber.penttest.phase;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.concurrent.TimeUnit;

@Component
@Slf4j
public class ToolRunner {

    private static final int DEFAULT_TIMEOUT_MINUTES = 10;

    public String run(String... args) {
        try {
            ProcessBuilder pb = new ProcessBuilder(args);
            pb.redirectErrorStream(true);
            Process process = pb.start();
            boolean finished = process.waitFor(DEFAULT_TIMEOUT_MINUTES, TimeUnit.MINUTES);
            if (!finished) {
                process.destroyForcibly();
                return "[TIMEOUT after " + DEFAULT_TIMEOUT_MINUTES + " minutes]";
            }
            return new String(process.getInputStream().readAllBytes());
        } catch (IOException | InterruptedException e) {
            log.warn("Tool execution failed: {} — {}", args[0], e.getMessage());
            return "[ERROR: " + e.getMessage() + "]";
        }
    }

    public String run(String[] args, String kubeconfig) {
        try {
            ProcessBuilder pb = new ProcessBuilder(args);
            pb.environment().put("KUBECONFIG", kubeconfig);
            pb.redirectErrorStream(true);
            Process process = pb.start();
            process.waitFor(DEFAULT_TIMEOUT_MINUTES, TimeUnit.MINUTES);
            return new String(process.getInputStream().readAllBytes());
        } catch (IOException | InterruptedException e) {
            log.warn("Tool execution failed: {} — {}", args[0], e.getMessage());
            return "[ERROR: " + e.getMessage() + "]";
        }
    }
}
