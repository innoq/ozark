/*
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 *
 * Copyright (c) 2015 Oracle and/or its affiliates. All rights reserved.
 *
 * The contents of this file are subject to the terms of either the GNU
 * General Public License Version 2 only ("GPL") or the Common Development
 * and Distribution License("CDDL") (collectively, the "License").  You
 * may not use this file except in compliance with the License.  You can
 * obtain a copy of the License at
 * http://glassfish.java.net/public/CDDL+GPL_1_1.html
 * or packager/legal/LICENSE.txt.  See the License for the specific
 * language governing permissions and limitations under the License.
 *
 * When distributing the software, include this License Header Notice in each
 * file and include the License file at packager/legal/LICENSE.txt.
 *
 * GPL Classpath Exception:
 * Oracle designates this particular file as subject to the "Classpath"
 * exception as provided by Oracle in the GPL Version 2 section of the License
 * file that accompanied this code.
 *
 * Modifications:
 * If applicable, add the following below the License Header, with the fields
 * enclosed by brackets [] replaced by your own identifying information:
 * "Portions Copyright [year] [name of copyright owner]"
 *
 * Contributor(s):
 * If you wish your version of this file to be governed by only the CDDL or
 * only the GPL Version 2, indicate your decision by adding "[Contributor]
 * elects to include this software in this distribution under the [CDDL or GPL
 * Version 2] license."  If you don't indicate a single choice of license, a
 * recipient has the option to distribute your version of this file under
 * either the CDDL, the GPL Version 2 or to extend the choice of license to
 * its licensees as provided above.  However, if you add GPL Version 2 code
 * and therefore, elected the GPL Version 2 license, then the option applies
 * only if the new code is made subject to such option by the copyright
 * holder.
 */
package org.glassfish.ozark.core;

import org.glassfish.ozark.event.BeforeControllerEventImpl;

import javax.annotation.Priority;
import javax.enterprise.event.Event;
import javax.inject.Inject;
import javax.mvc.annotation.Controller;
import javax.mvc.event.BeforeControllerEvent;
import javax.ws.rs.Priorities;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.container.ResourceInfo;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.UriInfo;
import java.io.IOException;

import static org.glassfish.ozark.cdi.OzarkCdiExtension.isEventObserved;

/**
 * <p>A JAX-RS request filter that fires a {@link javax.mvc.event.BeforeControllerEvent}
 * after the controller has been matched but before it is called.</p>
 *
 * <p>Given that this filter is annotated with {@link javax.mvc.annotation.Controller},
 * it will be called before a controller is called. Priority is set to
 * {@link javax.ws.rs.Priorities#ENTITY_CODER} which means it will be executed
 * right before user-defined request filters.</p>
 *
 * @author Santiago Pericas-Geertsen
 */
@Controller
@Priority(Priorities.ENTITY_CODER)
public class ViewRequestFilter implements ContainerRequestFilter {

    @Context
    private UriInfo uriInfo;

    @Context
    private ResourceInfo resourceInfo;

    @Inject
    private Event<BeforeControllerEvent> dispatcher;

    @Override
    public void filter(ContainerRequestContext requestContext) throws IOException {
        // Fire BeforeControllerEvent event
        if (isEventObserved(BeforeControllerEvent.class)) {
            final BeforeControllerEventImpl event = new BeforeControllerEventImpl();
            event.setUriInfo(uriInfo);
            event.setResourceInfo(resourceInfo);
            event.setContainerRequestContext(requestContext);
            dispatcher.fire(event);
        }
    }
}
