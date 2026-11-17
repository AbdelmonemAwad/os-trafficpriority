{#
 # SPDX-License-Identifier: BSD-2-Clause
 # Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
 #
 # Firewall: Traffic Priority (XGS: Traffic Priority when os-xgs-npu is installed) - the classes, each
 # marking the connections it matches with a DSCP through pf, and what pf holds of each one.
 #}

<style>
    /* KIT-CSS-BEGIN */
    .xgs-cards { display: flex; flex-wrap: wrap; gap: 12px; padding: 15px; }
    .xgs-cards.xgs-top { padding: 0 0 15px; }
    .xgs-card { flex: 1 1 200px; min-width: 190px; border: 1px solid rgba(128, 128, 128, 0.25);
                border-inline-start: 4px solid #9e9e9e; border-radius: 3px; padding: 10px 14px;
                background-color: rgba(128, 128, 128, 0.04); }
    .xgs-card.ok { border-inline-start-color: #5cb85c; }
    .xgs-card.warn { border-inline-start-color: #f0ad4e; }
    .xgs-card.bad { border-inline-start-color: #d9534f; }
    .xgs-card .k { font-size: 11px; text-transform: uppercase; letter-spacing: .04em; opacity: 0.6; }
    .xgs-card .v { font-size: 19px; font-weight: 600; line-height: 1.3; margin: 2px 0; }
    .xgs-card .s { font-size: 12px; opacity: 0.7; }
    .xgs-card .fa { opacity: 0.35; float: inline-end; font-size: 18px; margin-top: 2px; }
    .xgs-head { padding-top: 5px; padding-bottom: 5px; font-size: 16px; }
    /* KIT-CSS-END */
    /* A grid whose columns fill the width shows a one-pixel sideways bar when no vertical one takes
       the difference; wide screens never need to scroll it sideways. */
    @media (min-width: 768px) {
        #{{ formGridClass['table_id'] }} .tabulator-tableholder, #grid-applied .tabulator-tableholder { overflow-x: hidden; }
    }
</style>

<script>
    $(document).ready(function () {
        /* KIT-JS-BEGIN */
        /* A string as OPNsense's API and Volt's lang._() hand it over - escaped - made plain for .text(). */
        function plain(value) {
            return $('<textarea/>').html(value === null || value === undefined ? '' : String(value)).text();
        }

        /* One card: cls '' (grey, no judgement), 'ok', 'warn' or 'bad'; icon a Font Awesome name. */
        function card(cls, icon, key, value, sub) {
            return $('<div class="xgs-card"/>').addClass(cls)
                .append($('<i class="fa"/>').addClass(icon))
                .append($('<div class="k"/>').text(plain(key)))
                .append($('<div class="v"/>').text(plain(value)))
                .append($('<div class="s"/>').text(plain(sub || ' ')));
        }

        /* Until the first reading: the same cards, their keys, and an ellipsis for every value. */
        function cards_wait(target, keys) {
            $(target).empty();
            $.each(keys, function (i, key) {
                $(target).append(card('', 'fa-ellipsis-h', key, '…', ''));
            });
        }

        /* The selected tab kept in the address, as on OPNsense's own tabbed pages. */
        function keep_tab() {
            if (window.location.hash !== '') {
                $('a[href="' + window.location.hash + '"]').tab('show');
            }
            $('.nav-tabs a').on('shown.bs.tab', function (e) {
                history.pushState(null, null, e.target.hash);
            });
        }
        /* KIT-JS-END */

        function count(n) {
            return n === null || n === undefined || n === '' ? '-' : Number(n).toLocaleString();
        }

        /* Why a class makes no rule: the word Marking::problem() gives, the same test the rules hook makes. */
        const problems = {
            'id': "{{ lang._('ID not one the firewall made') }}",
            'description': "{{ lang._('description ends in a backslash') }}",
            'dscp': "{{ lang._('DSCP not one of 0 to 63') }}",
            'match': "{{ lang._('DSCP to match not one pf can match') }}",
            'protocol': "{{ lang._('protocol not known') }}",
            'port': "{{ lang._('port field not readable') }}",
            'ports': "{{ lang._('port without TCP or UDP') }}",
            'interface': "{{ lang._('interface field not readable') }}",
            'address': "{{ lang._('address field not readable') }}",
            'everything': "{{ lang._('nothing narrows it: it would mark every connection') }}",
            'family': "{{ lang._('no source and destination of its IP version') }}",
            'key': "{{ lang._('this OPNsense writes no mark on a rule') }}"
        };

        /*
         * Four cards: on or off, the classes switched on that pf holds rules for - and when pf refused the
         * last rule set, or this OPNsense writes no mark, that instead - the connections pf holds now with
         * a class's mark, each once (status.py's marked), and the switch's queues - not measured yet, so
         * nothing is set there.
         */
        function draw(data) {
            const $cards = $('#tp-cards').empty();
            $('#tp-refused, #tp-nokey').hide();
            if (!data || data.error) {
                $cards.append(card('bad', 'fa-power-off', "{{ lang._('Traffic Priority') }}", "{{ lang._('Status could not be read.') }}", ''));
                return;
            }
            const on = data.classes.filter(function (c) { return c.enabled; });
            const held = on.filter(function (c) { return c.rules > 0; });
            const wrong = data.refused || data.writes_mark === false;
            $cards.append(card(data.enabled ? 'ok' : '', 'fa-power-off', "{{ lang._('Traffic Priority') }}",
                data.enabled ? "{{ lang._('on') }}" : "{{ lang._('off') }}",
                on.length + ' ' + "{{ lang._('classes switched on') }}"));
            $cards.append(card(wrong ? 'bad' : (!data.enabled || !on.length ? '' : (held.length === on.length ? 'ok' : 'warn')),
                'fa-list', "{{ lang._('In pf') }}", held.length + ' / ' + on.length,
                !data.pf ? "{{ lang._('pf could not be asked') }}" :
                    data.writes_mark === false ? "{{ lang._('this OPNsense writes no mark on a rule') }}" :
                    data.refused ? "{{ lang._('last rule set refused by pf') }}" : "{{ lang._('classes with rules loaded') }}"));
            $cards.append(card('', 'fa-link', "{{ lang._('Marked now') }}", count(data.marked),
                "{{ lang._('connections with the DSCP of a class, each once') }}"));
            $cards.append(card('', 'fa-sitemap', "{{ lang._('Switch queues') }}", "{{ lang._('not measured yet') }}",
                "{{ lang._('DSCP written; no queue set') }}"));
            $('#tp-refused').toggle(!!data.refused);
            $('#tp-nokey').toggle(data.writes_mark === false);
            $('#tp-project').toggle(!!data.project);
            $('#tp-pf-alone').toggle(!data.project);
        }

        function refresh() {
            ajaxGet('/api/trafficpriority/service/status', {}, draw);
        }

        $("#{{ formGridClass['table_id'] }}").UIBootgrid({
            search: '/api/trafficpriority/settings/search_class',
            get: '/api/trafficpriority/settings/get_class/',
            set: '/api/trafficpriority/settings/set_class/',
            add: '/api/trafficpriority/settings/add_class/',
            del: '/api/trafficpriority/settings/del_class/',
            toggle: '/api/trafficpriority/settings/toggle_class/'
        });

        /* What pf holds of each class, from the status script by the class's label; the API escapes what
           it returns, so nothing here escapes it again. */
        $('#grid-applied').UIBootgrid({
            search: '/api/trafficpriority/service/search_applied',
            options: {
                selection: false,
                formatters: {
                    name: function (column, row) {
                        return '<span class="' + (row.enabled ? '' : 'text-muted') + '">' + row.description + '</span>';
                    },
                    inpf: function (column, row) {
                        if (!row.enabled) {
                            return '<span class="text-muted">' + "{{ lang._('off') }}" + '</span>';
                        }
                        if (row.problem) {
                            return '<span class="text-warning">' + "{{ lang._('no rule') }}" + ': ' +
                                (problems[row.problem] || row.problem) + '</span>';
                        }
                        const placed = row.not_placed ? ' · <span class="text-warning">' + count(row.not_placed) + ' ' +
                            "{{ lang._('not placed') }}" + '</span>' : '';
                        if (row.rules) {
                            return count(row.rules) + ' ' + "{{ lang._('rules') }}" + placed;
                        }
                        if (row.written) {
                            return '<span class="text-warning">' + "{{ lang._('written, not loaded') }}" + '</span>' + placed;
                        }
                        return "{{ lang._('not in pf') }}" + placed;
                    },
                    number: function (column, row) {
                        return count(row[column.id]);
                    },
                    queue: function (column, row) {
                        return '<span class="text-muted">' + "{{ lang._('not measured yet') }}" + '</span>';
                    }
                }
            }
        });

        /* The address and port fields offer what Firewall: Rules offers - aliases, interface networks -
           where the firewall's own lists can be read; else they stay text, as the model takes them. */
        ajaxGet('/api/firewall/filter/list_network_select_options', [], function (data) {
            if (!data || !data.single) {
                return;
            }
            $('.net_selector').each(function () {
                $(this).replaceInputWithSelector(data, $(this).hasClass('net_selector_multi'));
            });
        });
        ajaxGet('/api/firewall/filter/list_port_select_options', [], function (data) {
            if (!data || !data.single) {
                return;
            }
            $('.port_selector').each(function () {
                $(this).replaceInputWithSelector(data, false);
            });
        });

        mapDataToFormUI({'frm_general': '/api/trafficpriority/settings/get'}).done(function () {
            $('.selectpicker').selectpicker('refresh');
        });

        /* One Apply for the page: the General tab saved, then the filter reloaded, whose hook registers
           the classes' rules - OPNsense's own button, which says when there is something to apply. */
        $('#reconfigureAct').SimpleActionButton({
            onPreAction: function () {
                const saved = new $.Deferred();
                saveFormToEndpoint('/api/trafficpriority/settings/set', 'frm_general', function () {
                    saved.resolve();
                }, false, function () {
                    saved.reject();
                });
                return saved;
            },
            onAction: function () {
                refresh();
                $('#grid-applied').bootgrid('reload');
            }
        });

        /* the cards, and the grid of the tab on screen */
        $('#refreshAct').click(function () {
            refresh();
            const tab = $('#maintabs li.active a').attr('href');
            if (tab === '#classes') {
                $("#{{ formGridClass['table_id'] }}").bootgrid('reload');
            } else if (tab === '#applied') {
                $('#grid-applied').bootgrid('reload');
            }
        });

        cards_wait('#tp-cards', ["{{ lang._('Traffic Priority') }}", "{{ lang._('In pf') }}", "{{ lang._('Marked now') }}",
            "{{ lang._('Switch queues') }}"]);
        refresh();
        keep_tab();
    });
</script>

<div class="xgs-cards xgs-top" id="tp-cards"></div>
<div id="tp-refused" class="alert alert-danger" role="alert" style="display: none;">
    {{ lang._('pf refused the rule set of the last filter reload, and OPNsense loaded the one before it again: what pf holds of the classes is from that one. /tmp/rules.error says why.') }}
</div>
<div id="tp-nokey" class="alert alert-danger" role="alert" style="display: none;">
    {{ lang._('This OPNsense writes no pf scrub option on a rule, so no class is applied; the system log says so, under Traffic Priority.') }}
</div>
<div class="text-muted clearfix" style="padding: 0 0 10px;">
    <button id="refreshAct" class="btn btn-default btn-xs pull-right" type="button" title="{{ lang._('Refresh') }}"><i class="fa fa-fw fa-refresh"></i></button>
    {{ lang._('A class marks connections that come in on its interfaces and match it with its DSCP, both ways, written by pf. A connection keeps the mark it opened with: a change reaches new connections.') }}
</div>

<ul class="nav nav-tabs" data-tabs="tabs" id="maintabs">
    <li class="active"><a data-toggle="tab" href="#classes">{{ lang._('Classes') }}</a></li>
    <li><a data-toggle="tab" href="#applied">{{ lang._('Applied') }}</a></li>
    <li><a data-toggle="tab" href="#general">{{ lang._('General') }}</a></li>
</ul>

<div class="tab-content content-box">
    <div id="classes" class="tab-pane active">
        {{ partial('layout_partials/base_bootgrid_table', formGridClass) }}
    </div>
    <div id="applied" class="tab-pane">
        <table id="grid-applied" class="table table-condensed table-hover table-striped table-responsive">
            <thead>
                <tr>
                    <th data-column-id="uuid" data-type="string" data-identifier="true" data-visible="false">{{ lang._('ID') }}</th>
                    <th data-column-id="sequence" data-type="numeric" data-width="7em">{{ lang._('Sequence') }}</th>
                    <th data-column-id="description" data-formatter="name" data-type="string">{{ lang._('Class') }}</th>
                    <th data-column-id="dscp" data-type="string" data-width="9em">{{ lang._('DSCP') }}</th>
                    <th data-column-id="rules" data-formatter="inpf" data-type="string" data-sortable="false">{{ lang._('In pf') }}</th>
                    <th data-column-id="states" data-formatter="number" data-type="numeric" data-width="9em">{{ lang._('Matched now') }}</th>
                    <th data-column-id="created" data-formatter="number" data-type="numeric" data-width="10em">{{ lang._('Matched since reload') }}</th>
                    <th data-column-id="packets" data-formatter="number" data-type="numeric" data-visible="false">{{ lang._('Packets') }}</th>
                    <th data-column-id="bytes" data-formatter="number" data-type="numeric" data-visible="false">{{ lang._('Bytes') }}</th>
                    <th data-column-id="queue" data-formatter="queue" data-type="string" data-sortable="false" data-width="10em">{{ lang._('Switch queue') }}</th>
                </tr>
            </thead>
            <tbody></tbody>
            <tfoot></tfoot>
        </table>
        <div class="text-muted" style="padding: 0 15px 10px;">
            {{ lang._('Not in pf: class saved and not applied yet, or Traffic Priority off. Written, not loaded: the last filter reload wrote its rules and pf does not hold them. Not placed: OPNsense wrote its rule commented out - an interface not there, an address or a port it could not map.') }}
        </div>
        <div class="text-muted" style="padding: 0 15px 10px;">
            {{ lang._('Matched now, Matched since reload, packets and bytes: what pf counted for the rules of each class. Every filter reload, an Apply among them, starts them again from 0 - packets and bytes too, unless the firewall keeps counters - while connections keep their mark; and a connection two classes match is counted under both, keeping the mark of the lower sequence. Marked now, above, counts each connection pf holds with the DSCP of a class once, whenever it opened.') }}
        </div>
        <div id="tp-project" class="text-muted" style="display: none; padding: 0 15px 15px;">
            {{ lang._('os-xgs-npu is installed: it puts a marked IPv4 connection into hardware with its DSCP and keeps a marked IPv6 connection with the host - measured with a normalization rule, not yet with these rules. A connection in hardware adds no more packets or bytes here.') }}
        </div>
        <div id="tp-pf-alone" class="text-muted" style="display: none; padding: 0 15px 15px;">
            {{ lang._('pf alone marks connections here: without os-xgs-npu no hardware carries them.') }}
        </div>
    </div>
    <div id="general" class="tab-pane">
        {{ partial("layout_partials/base_form", ['fields': generalForm, 'id': 'frm_general']) }}
    </div>
</div>

{{ partial('layout_partials/base_apply_button', {'data_endpoint': '/api/trafficpriority/service/reconfigure'}) }}
{{ partial("layout_partials/base_dialog", ['fields': classForm, 'id': formGridClass['edit_dialog_id'], 'label': lang._('Edit class')]) }}
{{ partial("OPNsense/TrafficPriority/credit") }}
