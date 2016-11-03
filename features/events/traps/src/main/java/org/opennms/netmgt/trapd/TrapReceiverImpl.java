/*******************************************************************************
 * This file is part of OpenNMS(R).
 *
 * Copyright (C) 2002-2014 The OpenNMS Group, Inc.
 * OpenNMS(R) is Copyright (C) 1999-2014 The OpenNMS Group, Inc.
 *
 * OpenNMS(R) is a registered trademark of The OpenNMS Group, Inc.
 *
 * OpenNMS(R) is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License,
 * or (at your option) any later version.
 *
 * OpenNMS(R) is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with OpenNMS(R).  If not, see:
 *      http://www.gnu.org/licenses/
 *
 * For more information contact:
 *     OpenNMS(R) Licensing <license@opennms.org>
 *     http://www.opennms.org/
 *     http://www.opennms.com/
 *******************************************************************************/

package org.opennms.netmgt.trapd;

import java.io.IOException;
import java.lang.reflect.UndeclaredThrowableException;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

import org.opennms.core.logging.Logging;
import org.opennms.core.utils.InetAddressUtils;
import org.opennms.netmgt.config.TrapdConfig;
import org.opennms.netmgt.config.trapd.Snmpv3User;
import org.opennms.netmgt.config.trapd.TrapdConfiguration;
import org.opennms.netmgt.snmp.BasicTrapProcessorFactory;
import org.opennms.netmgt.snmp.SnmpUtils;
import org.opennms.netmgt.snmp.SnmpV3User;
import org.opennms.netmgt.snmp.TrapNotification;
import org.opennms.netmgt.snmp.TrapNotificationListener;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.Lists;

/**
 * @author <a href="mailto:weave@oculan.com">Brian Weaver</a>
 * @author <a href="http://www.oculan.com">Oculan Corporation</a>
 * @fiddler joed
 */
public class TrapReceiverImpl implements TrapReceiver, TrapNotificationListener {
    private static final Logger LOG = LoggerFactory.getLogger(TrapReceiverImpl.class);

    private class TrapdReceiverConfig {
        private String snmpTrapAddress;

        private int snmpTrapPort;

        private List<SnmpV3User> snmpV3Users = new ArrayList<>();

        private TrapdReceiverConfig() {

        }

        private TrapdReceiverConfig(TrapdConfig config) {
            snmpTrapPort = config.getSnmpTrapPort();
            snmpTrapAddress = config.getSnmpTrapAddress();
            if (config.getSnmpV3Users() != null) {
                snmpV3Users = Lists.newArrayList(config.getSnmpV3Users());
            }
        }

        private void update(TrapdConfiguration newConfig) {
            snmpTrapPort = newConfig.getSnmpTrapPort();
            snmpTrapAddress = newConfig.getSnmpTrapAddress();
            snmpV3Users = newConfig.getSnmpv3UserCollection().stream().map(user -> toSnmpV3User(user)).collect(Collectors.toList());
        }

        @Override
        public boolean equals(Object obj) {
            if (obj == this) return true;
            if (obj == null) return false;
            if (obj instanceof TrapdReceiverConfig) {
                final TrapdReceiverConfig other = (TrapdReceiverConfig) obj;
                boolean equals = Objects.equals(snmpTrapPort, other.snmpTrapPort)
                        && Objects.equals(snmpTrapAddress, other.snmpTrapAddress)
                        && Objects.equals(snmpV3Users, other.snmpV3Users);
                return equals;
            }
            return false;
        }

        @Override
        public int hashCode() {
            return Objects.hash(snmpTrapAddress, snmpTrapPort, snmpV3Users);
        }
    }

    private TrapdReceiverConfig config;

    private boolean m_registeredForTraps;

    private List<TrapNotificationHandler> m_trapNotificationHandlers = new ArrayList<TrapNotificationHandler>();

    public TrapReceiverImpl(final TrapdConfig config) {
        if (config == null) {
            throw new IllegalArgumentException("Config cannot be null");
        }
        this.config = new TrapdReceiverConfig(config);
    }

    public void setTrapdConfig(TrapdConfiguration newTrapdConfig) {
        if (checkForTrapdConfigurationChange(newTrapdConfig)) {

            LOG.info("Stopping TrapReceiver service to reload configuration...");
            stop();
            LOG.info("TrapReceiver service has been stopped.");

            synchronized (config) {
                config.update(newTrapdConfig);
            }

            LOG.info("Restarting the TrapReceiver service...");
            start();
            LOG.info("TrapReceiver service has been restarted.");
        }
    }

    protected boolean checkForTrapdConfigurationChange(TrapdConfiguration trapdConfiguration) {
        final TrapdReceiverConfig newConfig = new TrapdReceiverConfig();
        newConfig.update(trapdConfiguration);

        if (config.snmpTrapPort != newConfig.snmpTrapPort) {
            LOG.info("SNMP trap port has been updated from trapd-confguration.xml.");
            return true;
        } else if (config.snmpTrapAddress != null
                && !config.snmpTrapAddress.equalsIgnoreCase("*")
                && !config.snmpTrapAddress.equalsIgnoreCase(newConfig.snmpTrapAddress)) {
            LOG.info("SNMP trap address has been updated from trapd-confguration.xml.");
            return true;
        } else {
            if (!config.snmpV3Users.equals(newConfig.snmpV3Users)) {
                LOG.info("SNMPv3 user list has been updated from trapd-confguration.xml.");
                return true;
            }
        }

        return false;
    }

    public TrapNotificationHandler getTrapNotificationHandlers() {
        return m_trapNotificationHandlers.get(0);
    }

    public void setTrapNotificationHandlers(TrapNotificationHandler handler) {
        m_trapNotificationHandlers = Collections.singletonList(handler);
    }

    @Override
    public void trapReceived(TrapNotification trapNotification) {
        try {
            for (TrapNotificationHandler handler : m_trapNotificationHandlers) {
                handler.handleTrapNotification(trapNotification);
            }
        } catch (Throwable e) {
            LOG.error("Handler execution failed in {}", this.getClass().getSimpleName(), e);
        }
    }

    @Override
    public void trapError(int error, String msg) {
      LOG.warn("Error Processing Received Trap: error = {} {}", error, (msg != null ? ", ref = " + msg : ""));
    }

    @Override
    public void start(){
        try {
            InetAddress address = getInetAddress();
            LOG.info("Listening on {}:{}", address == null ? "[all interfaces]" : InetAddressUtils.str(address), config.snmpTrapPort);
            SnmpUtils.registerForTraps(this, new BasicTrapProcessorFactory(), address, config.snmpTrapPort, config.snmpV3Users); // Need to clarify
            m_registeredForTraps = true;
            
            LOG.debug("init: Creating the trap session");
        } catch (final IOException e) {
            if (e instanceof java.net.BindException) {
                Logging.withPrefix("OpenNMS.Manager", new Runnable() {
                    @Override
                    public void run() {
                        LOG.error("init: Failed to listen on SNMP trap port {}, perhaps something else is already listening?", config.snmpTrapPort, e);
                    }
                });
                LOG.error("init: Failed to listen on SNMP trap port {}, perhaps something else is already listening?", config.snmpTrapPort, e);
                throw new UndeclaredThrowableException(e, "Failed to listen on SNMP trap port {}" + config.snmpTrapPort + ", perhaps something else is already listening?");
            } else {
                LOG.error("init: Failed to initialize SNMP trap socket on port {}", config.snmpTrapPort, e);
                throw new UndeclaredThrowableException(e, "Failed to initialize SNMP trap socket on port " + config.snmpTrapPort);
            }
        }
    }

    @Override
    public void stop() {
        try {
            if (m_registeredForTraps) {
                LOG.debug("stop: Closing SNMP trap session.");
                SnmpUtils.unregisterForTraps(this, getInetAddress(), config.snmpTrapPort);
                LOG.debug("stop: SNMP trap session closed.");
            } else {
                LOG.debug("stop: not attemping to closing SNMP trap session--it was never opened");
            }

        } catch (final IOException e) {
            LOG.warn("stop: exception occurred closing session", e);
        } catch (final IllegalStateException e) {
            LOG.debug("stop: The SNMP session was already closed", e);
        }
    }

    private InetAddress getInetAddress() {
        if (config.snmpTrapAddress.equals("*")) {
            return null;
        }
        return InetAddressUtils.addr(config.snmpTrapAddress);
    }

    public static SnmpV3User toSnmpV3User(Snmpv3User snmpv3User) {
        SnmpV3User snmpV3User = new SnmpV3User();
        snmpV3User.setAuthPassPhrase(snmpv3User.getAuthPassphrase());
        snmpV3User.setAuthProtocol(snmpv3User.getAuthProtocol());
        snmpV3User.setEngineId(snmpv3User.getEngineId());
        snmpV3User.setPrivPassPhrase(snmpv3User.getPrivacyPassphrase());
        snmpV3User.setPrivProtocol(snmpv3User.getPrivacyProtocol());
        snmpV3User.setSecurityName(snmpv3User.getSecurityName());
        return snmpV3User;
    }
}
