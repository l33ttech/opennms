/*******************************************************************************
 * This file is part of OpenNMS(R).
 *
 * Copyright (C) 2016 The OpenNMS Group, Inc.
 * OpenNMS(R) is Copyright (C) 1999-2016 The OpenNMS Group, Inc.
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

package org.opennms.core.ipc.sink.camel;

import java.util.HashMap;
import java.util.Map;

import org.apache.camel.Endpoint;
import org.apache.camel.EndpointInject;
import org.apache.camel.ProducerTemplate;
import org.opennms.core.ipc.sink.api.SinkModule;
import org.opennms.core.camel.JmsQueueNameFactory;
import org.opennms.core.ipc.sink.api.Message;
import org.opennms.core.ipc.sink.api.MessageProducer;
import org.opennms.core.ipc.sink.api.MessageProducerFactory;

/**
 * Message producer that sends messages via JMS.
 *
 * @author jwhite
 */
public class CamelRemoteMessageProducerFactory implements MessageProducerFactory {

    @EndpointInject(uri = "direct:sendMessage", context = "sinkClient")
    private ProducerTemplate template;

    @EndpointInject(uri = "direct:sendMessage", context = "sinkClient")
    private Endpoint endpoint;

    @Override
    public <T extends Message> MessageProducer<T> getProducer(SinkModule<T> module) {
        return new MessageProducer<T>() {
            @Override
            public void send(T message) {
                final JmsQueueNameFactory queueNameFactory = new JmsQueueNameFactory(
                        CamelSinkConstants.JMS_QUEUE_PREFIX, module.getId());
                Map<String, Object> headers = new HashMap<>();
                headers.put(CamelSinkConstants.JMS_QUEUE_NAME_HEADER, queueNameFactory.getName());
                template.sendBodyAndHeaders(endpoint, module.marshal(message), headers);
            }
        };
    }
}
