package com.jelurida.ardor.contracts;

import nxt.SafeShutdownSuite;
import org.junit.runner.RunWith;
import org.junit.runners.Suite;

@RunWith(Suite.class)
@Suite.SuiteClasses({
        IdentityVerificationTest.class,
})
public class ContractRunnerSuite extends SafeShutdownSuite {
}
