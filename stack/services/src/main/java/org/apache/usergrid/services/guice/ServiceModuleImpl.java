/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.usergrid.services.guice;


import org.apache.usergrid.corepersistence.ServiceModule;
import org.apache.usergrid.management.AppInfoMigrationPlugin;
import org.apache.usergrid.persistence.core.migration.data.MigrationPlugin;

import com.google.inject.AbstractModule;
import com.google.inject.multibindings.Multibinder;


/**
 * Module that handles all of the guice injects for services.
 */


/**
 *   <bean id="notificationsQueueListener" class="org.apache.usergrid.services.notifications.QueueListener"
 scope="singleton">
 <constructor-arg name="emf" ref="entityManagerFactory" />
 <constructor-arg name="metricsService" ref="metricsFactory" />
 <constructor-arg name="props" ref="properties" />
 <constructor-arg name="smf" ref="serviceManagerFactory" />
 </bean>
 */

public class ServiceModuleImpl extends AbstractModule implements ServiceModule {
    @Override
    protected void configure() {

        //Seems weird, aren't we just binding the factory to the exact same factory when it goes to look for it?
        final Multibinder<MigrationPlugin> plugins = Multibinder.newSetBinder( binder(), MigrationPlugin.class );
        plugins.addBinding().to(AppInfoMigrationPlugin.class);

    }
}
