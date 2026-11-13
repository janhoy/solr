/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.solr.cats.env;

/**
 * The shape of the port block the program under test needs, which the harness hands out one of per
 * test class.
 *
 * <p>Ports belong to the program rather than to the harness: a server may need several, a text
 * utility none. {@link #NONE} is the latter.
 */
public final class PortLayout {

  /** A program that listens on nothing. */
  public static final PortLayout NONE = new PortLayout();

  private PortLayout() {}
}
