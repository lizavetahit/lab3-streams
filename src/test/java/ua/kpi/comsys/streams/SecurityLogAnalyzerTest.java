package ua.kpi.comsys.streams;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

//  якщо стрім зависне, тест буде перервано і він впаде через 2 секунди
@Timeout(value = 2, unit = TimeUnit.SECONDS, threadMode = Timeout.ThreadMode.SEPARATE_THREAD)
class SecurityLogAnalyzerTest {

    private static final LocalDateTime START = LocalDateTime.of(2025, 1, 1, 12, 0);

    private SecurityLogAnalyzer analyzer;

    @BeforeEach
    void setUp() {
        analyzer = new SecurityLogAnalyzer();
    }

    private static SecurityLog log(String ip, String severity, int minute) {
        return new SecurityLog(ip, severity, "event " + minute, START.plusMinutes(minute));
    }

    private static SecurityLog log(String ip) {
        return log(ip, "INFO", 0);
    }

    // Нескінченний потік (кожна подія на хвилину пізніше)
    private static Stream<SecurityLog> infiniteLogs() {
        return Stream.iterate(0, i -> i + 1)
                .map(i -> log("10.0.0." + (i % 5), "INFO", i));
    }

    @Nested
    @DisplayName("findFirstCriticalEvent")
    class FindFirstCriticalEvent {

        @Test
        @DisplayName("finds CRITICAL event in an infinite stream")
        void findsInInfiniteStream() {
            Stream<SecurityLog> stream = Stream.iterate(0, i -> i + 1)
                    .map(i -> log("10.0.0.1", i == 1000 ? "CRITICAL" : "WARNING", i));

            Optional<SecurityLog> result = analyzer.findFirstCriticalEvent(stream);

            assertEquals(Optional.of("event 1000"), result.map(SecurityLog::eventDescription));
        }

        @Test
        @DisplayName("stops reading the stream right after the first match (lazy)")
        void isLazy() {
            AtomicInteger consumed = new AtomicInteger();
            Stream<SecurityLog> stream = Stream.iterate(0, i -> i + 1)
                    .peek(i -> consumed.incrementAndGet())
                    .map(i -> log("10.0.0.1", i == 9 ? "CRITICAL" : "INFO", i));

            analyzer.findFirstCriticalEvent(stream);

            assertEquals(10, consumed.get());
        }

        @Test
        @DisplayName("returns the first of several CRITICAL events")
        void returnsFirstMatch() {
            Stream<SecurityLog> stream = Stream.of(
                    log("1.1.1.1", "INFO", 0),
                    log("2.2.2.2", "CRITICAL", 1),
                    log("3.3.3.3", "CRITICAL", 2));

            Optional<String> ip = analyzer.findFirstCriticalEvent(stream).map(SecurityLog::ipAddress);

            assertEquals(Optional.of("2.2.2.2"), ip);
        }

        @Test
        @DisplayName("severity is case-insensitive and ignores spaces")
        void caseInsensitive() {
            Stream<SecurityLog> stream = Stream.of(log("1.1.1.1", "info", 0), log("2.2.2.2", " Critical ", 1));

            assertTrue(analyzer.findFirstCriticalEvent(stream).isPresent());
        }

        @Test
        @DisplayName("finite stream without CRITICAL -> Optional.empty()")
        void emptyWhenNotFound() {
            Stream<SecurityLog> stream = infiniteLogs().limit(100);

            assertEquals(Optional.empty(), analyzer.findFirstCriticalEvent(stream));
        }

        @Test
        @DisplayName("empty stream -> Optional.empty()")
        void emptyStream() {
            assertTrue(analyzer.findFirstCriticalEvent(Stream.empty()).isEmpty());
        }

        @Test
        @DisplayName("null elements and null severity are skipped")
        void skipsNulls() {
            Stream<SecurityLog> stream = Stream.of(null, log("1.1.1.1", null, 0), log("2.2.2.2", "CRITICAL", 1));

            assertEquals(Optional.of("2.2.2.2"),
                    analyzer.findFirstCriticalEvent(stream).map(SecurityLog::ipAddress));
        }

        @Test
        @DisplayName("null stream -> IllegalArgumentException")
        void nullStream() {
            assertThrows(IllegalArgumentException.class, () -> analyzer.findFirstCriticalEvent(null));
        }
    }

    @Nested
    @DisplayName("getLogsBeforeDeadline")
    class GetLogsBeforeDeadline {

        @Test
        @DisplayName("collects logs from an infinite stream until the deadline")
        void infiniteStream() {
            List<SecurityLog> result = analyzer.getLogsBeforeDeadline(infiniteLogs(), START.plusMinutes(10));

            assertEquals(10, result.size());
            assertEquals(START, result.get(0).timestamp());
            assertEquals(START.plusMinutes(9), result.get(9).timestamp());
        }

        @Test
        @DisplayName("log exactly at the deadline is not included")
        void deadlineIsExclusive() {
            List<SecurityLog> result = analyzer.getLogsBeforeDeadline(infiniteLogs(), START.plusMinutes(3));

            assertTrue(result.stream().allMatch(l -> l.timestamp().isBefore(START.plusMinutes(3))));
            assertEquals(3, result.size());
        }

        @Test
        @DisplayName("deadline before the first log -> empty list (infinite stream)")
        void deadlineBeforeFirstLog() {
            assertTrue(analyzer.getLogsBeforeDeadline(infiniteLogs(), START.minusMinutes(1)).isEmpty());
        }

        @Test
        @DisplayName("stops at the first log after the deadline (takeWhile)")
        void stopsAtFirstLateLog() {
            Stream<SecurityLog> stream = Stream.of(
                    log("1.1.1.1", "INFO", 1),
                    log("1.1.1.1", "INFO", 20),
                    log("1.1.1.1", "INFO", 2));

            List<SecurityLog> result = analyzer.getLogsBeforeDeadline(stream, START.plusMinutes(10));

            assertEquals(1, result.size());
        }

        @Test
        @DisplayName("finite stream entirely before the deadline -> all logs")
        void allBeforeDeadline() {
            List<SecurityLog> result = analyzer.getLogsBeforeDeadline(infiniteLogs().limit(5), START.plusDays(1));

            assertEquals(5, result.size());
        }

        @Test
        @DisplayName("null elements are skipped")
        void skipsNullElements() {
            Stream<SecurityLog> stream = Stream.of(log("1.1.1.1", "INFO", 1), null, log("2.2.2.2", "INFO", 2));

            assertEquals(2, analyzer.getLogsBeforeDeadline(stream, START.plusMinutes(10)).size());
        }

        @Test
        @DisplayName("log without timestamp stops collection")
        void nullTimestampStops() {
            Stream<SecurityLog> stream = Stream.of(
                    log("1.1.1.1", "INFO", 1),
                    new SecurityLog("2.2.2.2", "INFO", "no time", null),
                    log("3.3.3.3", "INFO", 2));

            assertEquals(1, analyzer.getLogsBeforeDeadline(stream, START.plusMinutes(10)).size());
        }

        @Test
        @DisplayName("null stream or deadline -> IllegalArgumentException")
        void nullArguments() {
            assertThrows(IllegalArgumentException.class,
                    () -> analyzer.getLogsBeforeDeadline(null, START));
            assertThrows(IllegalArgumentException.class,
                    () -> analyzer.getLogsBeforeDeadline(infiniteLogs(), null));
        }
    }

    @Nested
    @DisplayName("detectIpBursts")
    class DetectIpBursts {

        @Test
        @DisplayName("infinite stream: each IP sends 3 events in a row, limit 4 IPs")
        void infiniteStreamWithLimit() {
            Stream<SecurityLog> stream = Stream.iterate(0, i -> i + 1)
                    .map(i -> log("192.168.0." + (i / 3)));

            List<String> result = analyzer.detectIpBursts(stream, 3, 4);

            assertEquals(List.of("192.168.0.0", "192.168.0.1", "192.168.0.2", "192.168.0.3"), result);
        }

        @Test
        @DisplayName("infinite stream from a single IP stops after the first burst")
        void singleIpInfiniteStream() {
            Stream<SecurityLog> stream = Stream.generate(() -> log("6.6.6.6"));

            assertEquals(List.of("6.6.6.6"), analyzer.detectIpBursts(stream, 5, 1));
        }

        @Test
        @DisplayName("stops reading the stream as soon as the limit is reached (lazy)")
        void isLazy() {
            AtomicInteger consumed = new AtomicInteger();
            Stream<SecurityLog> stream = Stream.iterate(0, i -> i + 1)
                    .peek(i -> consumed.incrementAndGet())
                    .map(i -> log("192.168.0." + (i / 2)));

            analyzer.detectIpBursts(stream, 2, 3);

            assertEquals(6, consumed.get());
        }

        @Test
        @DisplayName("interleaved IPs are not a burst")
        void interleavedIsNotBurst() {
            Stream<SecurityLog> stream = Stream.of(log("A"), log("B"), log("A"), log("B"), log("A"));

            assertTrue(analyzer.detectIpBursts(stream, 2, 10).isEmpty());
        }

        @Test
        @DisplayName("streak shorter than the threshold is not reported")
        void shortStreak() {
            Stream<SecurityLog> stream = Stream.of(log("A"), log("A"), log("B"), log("A"), log("A"));

            assertTrue(analyzer.detectIpBursts(stream, 3, 10).isEmpty());
        }

        @Test
        @DisplayName("same IP is reported only once")
        void reportedOnce() {
            Stream<SecurityLog> stream = Stream.of(
                    log("A"), log("A"), log("B"), log("A"), log("A"), log("A"));

            assertEquals(List.of("A"), analyzer.detectIpBursts(stream, 2, 10));
        }

        @Test
        @DisplayName("IPs are reported in the order bursts happen")
        void keepsOrder() {
            Stream<SecurityLog> stream = Stream.of(log("B"), log("B"), log("A"), log("A"), log("C"));

            assertEquals(List.of("B", "A"), analyzer.detectIpBursts(stream, 2, 10));
        }

        @Test
        @DisplayName("threshold 1: every new IP is a burst")
        void thresholdOne() {
            Stream<SecurityLog> stream = Stream.of(log("A"), log("A"), log("B"), log("C"));

            assertEquals(List.of("A", "B", "C"), analyzer.detectIpBursts(stream, 1, 10));
        }

        @Test
        @DisplayName("null event or null IP breaks the streak")
        void nullBreaksStreak() {
            Stream<SecurityLog> stream = Stream.of(log("A"), null, log("A"), log(null), log("A"));

            assertTrue(analyzer.detectIpBursts(stream, 2, 10).isEmpty());
        }

        @Test
        @DisplayName("works with a downstream limit()")
        void respectsDownstreamLimit() {
            Stream<SecurityLog> source = Stream.iterate(0, i -> i + 1)
                    .map(i -> log("10.1.1." + (i / 2)));
            IpBurstGatherer gatherer = new IpBurstGatherer(2, 100);

            List<String> result = source.gather(gatherer).limit(2).toList();

            assertEquals(List.of("10.1.1.0", "10.1.1.1"), result);
        }

        @Test
        @DisplayName("invalid arguments -> IllegalArgumentException")
        void invalidArguments() {
            assertThrows(IllegalArgumentException.class, () -> analyzer.detectIpBursts(null, 2, 2));
            assertThrows(IllegalArgumentException.class, () -> analyzer.detectIpBursts(infiniteLogs(), 0, 2));
            assertThrows(IllegalArgumentException.class, () -> analyzer.detectIpBursts(infiniteLogs(), -1, 2));
            assertThrows(IllegalArgumentException.class, () -> analyzer.detectIpBursts(infiniteLogs(), 2, 0));
            assertThrows(IllegalArgumentException.class, () -> new IpBurstGatherer(2, -5));
        }
    }
}
