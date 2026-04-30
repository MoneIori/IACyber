package com.iacyber.penttest.phase;

import com.iacyber.penttest.domain.PhaseResult;
import com.iacyber.penttest.domain.PentestSession;

public interface AttackPhaseExecutor {

    PhaseResult.AttackPhase phase();

    /**
     * Esegue la fase di attacco.
     * Ogni implementazione usa i tool appropriati e restituisce
     * un PhaseResult con rawOutput + findingsJson strutturato.
     */
    PhaseResult execute(PentestSession session);

    /**
     * Indica se questa fase richiede un livello minimo di aggressività.
     */
    PentestSession.AggressivenessLevel minimumAggressiveness();
}
