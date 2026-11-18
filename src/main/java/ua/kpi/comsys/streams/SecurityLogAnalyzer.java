package ua.kpi.comsys.streams;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Stream;

public class SecurityLogAnalyzer {

    private static final String CRITICAL = "CRITICAL";

    // Знайти першу критичну подію в нескінченному потоці логів
    public Optional<SecurityLog> findFirstCriticalEvent(Stream<SecurityLog> stream) {
        requireStream(stream);
        return stream
                .filter(SecurityLogAnalyzer::isCritical)
                .findFirst();
    }

    // Фільтрувати логи за часовим вікном у нескінченному потоці
    public List<SecurityLog> getLogsBeforeDeadline(Stream<SecurityLog> stream, LocalDateTime deadline) {
        requireStream(stream);
        if (deadline == null) {
            throw new IllegalArgumentException("deadline cannot be null");
        }
        return stream
                .filter(Objects::nonNull)
                .takeWhile(log -> isBefore(log, deadline))
                .toList();
    }


    public List<String> detectIpBursts(Stream<SecurityLog> stream, int burstThreshold, int maxIpsToReport) {
        requireStream(stream);
        IpBurstGatherer gatherer = new IpBurstGatherer(burstThreshold, maxIpsToReport);
        return stream
                .gather(gatherer)
                .toList();
    }

    private static boolean isCritical(SecurityLog log) {
        return Optional.ofNullable(log)
                .map(SecurityLog::severityLevel)
                .map(String::strip)
                .filter(CRITICAL::equalsIgnoreCase)
                .isPresent();
    }

    private static boolean isBefore(SecurityLog log, LocalDateTime deadline) {
        return Optional.ofNullable(log.timestamp())
                .filter(timestamp -> timestamp.isBefore(deadline))
                .isPresent();
    }

    private static void requireStream(Stream<SecurityLog> stream) {
        if (stream == null) {
            throw new IllegalArgumentException("stream cannot be null");
        }
    }
}
