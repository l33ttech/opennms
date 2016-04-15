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

package org.opennms.netmgt.bsm.vaadin.adminpage;

import java.util.Objects;

import org.opennms.netmgt.bsm.service.model.BusinessService;

/**
 * Used to list {@link BusinessService}s in a {@link com.vaadin.ui.TreeTable}.
 *
 * This allows the rows to have alternate IDs, since the business services may have
 * multiple parents.
 *
 * @author jwhite
 */
public class BusinessServiceRow {

    private final long id;
    private final BusinessService businessService;
    
    public BusinessServiceRow(BusinessService businessService, long id) {
        this.businessService = Objects.requireNonNull(businessService);
        this.id = id;
    }

    public long getId() {
        return id;
    }

    public String getName() {
        return businessService.getName();
    }

    public BusinessService getBusinessService() {
        return businessService;   
    }
}
