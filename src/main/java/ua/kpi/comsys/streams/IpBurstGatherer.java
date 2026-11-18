package ua.kpi.comsys.streams;

import java.util.HashSet;
import java.util.Set;
import java.util.function.Supplier;
import java.util.stream.Gatherer;


public class IpBurstGatherer implements Gatherer<SecurityLog, IpBurstGatherer.State, String> {

    private final int burstThreshold;
    private final int maxIpsToReport;

    public IpBurstGatherer(int burstThreshold, int maxIpsToReport) {
        if (burstThreshold <= 0) {
            throw new IllegalArgumentException("burstThreshold must be greater than 0");
        }
        if (maxIpsToReport <= 0) {
            throw new IllegalArgumentException("maxIpsToReport must be greater than 0");
        }
        this.burstThreshold = burstThreshold;
        this.maxIpsToReport = maxIpsToReport;
    }

    // поточна IP, довжина її неперервної серії та вже знайдені IP
    static final class State {
        private String currentIp;
        private int streak;
        private final Set<String> reportedIps = new HashSet<>();
    }

    @Override
    public Supplier<State> initializer() {
        return State::new;
    }

    @Override
    public Integrator<State, SecurityLog, String> integrator() {
        return Integrator.of((state, log, downstream) -> {
            String ip = (log == null) ? null : log.ipAddress();

            if (ip == null) {
                // некоректна подія перериває серію
                state.currentIp = null;
                state.streak = 0;
                return true;
            }

            if (ip.equals(state.currentIp)) {
                state.streak++;
            } else {
                state.currentIp = ip;
                state.streak = 1;
            }

            if (state.streak == burstThreshold && state.reportedIps.add(ip)) {
                if (!downstream.push(ip)) {
                    return false;
                }
            }

            // false -> більше елементів не потрібно, нескінченний стрім зупиняється
            return state.reportedIps.size() < maxIpsToReport;
        });
    }
}
