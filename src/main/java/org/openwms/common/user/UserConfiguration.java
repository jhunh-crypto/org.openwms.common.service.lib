package org.openwms.common.user;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Clock;

/**
 * Uhr für Anmeldesperren und Token-Ablauf. Eine vorhandene Clock-Bean (z. B. in Tests) hat Vorrang.
 */
@Configuration
public class UserConfiguration {

    @Bean
    @ConditionalOnMissingBean(Clock.class)
    Clock clock() {
        return Clock.systemDefaultZone();
    }
}
