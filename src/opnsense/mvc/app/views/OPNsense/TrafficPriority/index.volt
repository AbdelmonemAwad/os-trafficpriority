{#
 # SPDX-License-Identifier: BSD-2-Clause
 # Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
 #
 # Firewall: Traffic Priority (XGS: Traffic Priority when os-xgs-npu is installed) - the classes, each
 # marking the connections it matches with a DSCP through pf, what pf holds of each one, its place in
 # an XGS appliance's switch queues, and each rule of Firewall: Shaper with what the switch takes of it.
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
        #{{ formGridClass['table_id'] }} .tabulator-tableholder, #grid-applied .tabulator-tableholder,
        #grid-shaper .tabulator-tableholder { overflow-x: hidden; }
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

        /* A text with %s in it, each filled in turn. */
        function fill(text) {
            const args = Array.prototype.slice.call(arguments, 1);
            return String(text).replace(/%s/g, function () {
                return args.length ? String(args.shift()) : '';
            });
        }

        /* A rate in kbit/s, as a person reads it. */
        function rate(kbit) {
            if (kbit === null || kbit === undefined) {
                return '-';
            }
            if (kbit >= 1000000 && kbit % 100000 === 0) {
                return (kbit / 1000000) + ' Gbit/s';
            }
            if (kbit >= 1000 && kbit % 1000 === 0) {
                return (kbit / 1000) + ' Mbit/s';
            }
            return kbit + ' kbit/s';
        }

        /* Why the switch is not set at all (status.py's hardware.why_not, apply.py's decision). */
        const switchNot = {
            'plugin-off': "{{ lang._('Traffic Priority is off') }}",
            'no-project': "{{ lang._('no switch here: pf alone marks') }}",
            'no-tool': "{{ lang._('this os-xgs-npu sets no switch queue yet: update it') }}",
            'read-only': "{{ lang._('not applied on this model yet: os-xgs-npu only reads its switch') }}",
            'no-switch': "{{ lang._('no switch os-xgs-npu knows on this model') }}",
            'follow-off': "{{ lang._('Follow Firewall: Shaper is off (General)') }}",
            'unknown': "{{ lang._('not known') }}"
        };

        /* A class's place in the switch (hardware.py's plan). */
        function place(sw, not) {
            if (not) {
                return '<span class="text-muted">' + (switchNot[not] || not) + '</span>';
            }
            if (!sw) {
                return '-';
            }
            let text;
            switch (sw.why) {
                case 'hardware':
                    text = sw.kind === 'strict' ? fill("{{ lang._('queue %s, strict') }}", sw.queue) :
                        fill("{{ lang._('queue %s, weighted: %s percent of a full port at least') }}", sw.queue, sw.percent);
                    break;
                case 'third':
                    text = '<span class="text-warning">' + "{{ lang._('pf only: the switch takes two DSCPs, and two come before it') }}" + '</span>';
                    break;
                case 'best-effort':
                    text = "{{ lang._('queue 0, with everything else') }}";
                    break;
                case 'ipv6':
                    text = "{{ lang._('queue 0: the switch picks out IPv4 alone') }}";
                    break;
                case 'dscp':
                    text = '<span class="text-warning">' + "{{ lang._('DSCP not one of 0 to 63') }}" + '</span>';
                    break;
                default:
                    text = '<span class="text-muted">' + "{{ lang._('off') }}" + '</span>';
            }
            if (sw.minimum_why === 'not-hardware') {
                text += ' · <span class="text-warning">' + "{{ lang._('its minimum is not held: no queue of its own') }}" + '</span>';
            } else if (sw.minimum_why === 'over') {
                text += ' · <span class="text-warning">' + "{{ lang._('its minimum is not held: the minimums add up to more than 100 percent') }}" + '</span>';
            }
            return text;
        }

        /* What the switch takes of a rule of Firewall: Shaper, and what stays with the host (shaper_map.py). */
        const shaperHost = {
            'off': "{{ lang._('switched off in Firewall: Shaper') }}",
            'target-off': "{{ lang._('its pipe or queue is off or gone') }}",
            'per-host': "{{ lang._('a limit for each address, by its pipe\'s mask: the switch limits a port') }}",
            'not-switch-port': "{{ lang._('its interface is not a front port behind the switch') }}",
            'rate': "{{ lang._('a rate the switch cannot set: 64 kbit/s to 10 Gbit/s') }}",
            'way-in': "{{ lang._('the way in: the switch limits what leaves a port') }}",
            'port-taken': "{{ lang._('an earlier rule limits this port: %s') }}",
            'no-dscp': "{{ lang._('it matches no DSCP: the switch tells traffic apart by a DSCP alone') }}",
            'dscp-name': "{{ lang._('a DSCP this page does not know') }}",
            'class-limit': "{{ lang._('its pipe\'s %s for this traffic alone: the switch limits a port, not a class') }}",
            'dscps': "{{ lang._('more than one DSCP: each has a queue of its own in the switch') }}",
            'best-effort': "{{ lang._('Best Effort is the switch\'s queue 0, with everything else') }}",
            'unmarked': "{{ lang._('no class here marks DSCP %s') }}",
            'pf-only': "{{ lang._('DSCP %s is marked by pf only: the switch takes two DSCPs') }}",
            'dscp-only': "{{ lang._('its other conditions are not the switch\'s: it picks out the DSCP alone') }}",
            'one-queue': "{{ lang._('the only queue of its pipe: its weight shares nothing') }}",
            'minimum-wins': "{{ lang._('a class\'s own minimum for DSCP %s is held instead') }}",
            'share-taken': "{{ lang._('an earlier rule gave DSCP %s its part: %s') }}",
            'share-over': "{{ lang._('its part, %s percent, would take the parts past 100 percent') }}"
        };

        function shaperHardware(row) {
            if (!row.hardware || !row.hardware.length) {
                return '<span class="text-muted">-</span>';
            }
            return row.hardware.map(function (item) {
                if (item.what === 'limit') {
                    return fill("{{ lang._('%s: egress limit %s') }}", item.port, rate(item.kbit));
                }
                if (item.what === 'share') {
                    return fill("{{ lang._('DSCP %s: %s percent of every port at least, queue %s') }}", item.dscp, item.percent, item.queue);
                }
                return fill("{{ lang._('DSCP %s in queue %s') }}", item.dscp, item.queue);
            }).join('<br/>');
        }

        function shaperStays(row) {
            if (!row.host || !row.host.length) {
                return '<span class="text-muted">-</span>';
            }
            return row.host.map(function (item) {
                const text = switchNot[item.why] || shaperHost[item.why] || item.why;
                switch (item.why) {
                    case 'port-taken':
                    case 'share-taken':
                        return item.why === 'port-taken' ? fill(text, item.by) : fill(text, item.dscp, item.by);
                    case 'class-limit':
                        return fill(text, rate(item.kbit));
                    case 'unmarked':
                    case 'pf-only':
                    case 'minimum-wins':
                        return fill(text, item.dscp);
                    case 'share-over':
                        return fill(text, item.percent);
                }
                return text;
            }).join('<br/>');
        }

        const directions = {
            'in': "{{ lang._('in') }}",
            'out': "{{ lang._('out') }}",
            '': "{{ lang._('both ways') }}"
        };

        /*
         * Four cards: on or off, the classes switched on that pf holds rules for - and when pf refused the
         * last rule set, or this OPNsense writes no mark, that instead - the connections pf holds now with
         * a mark set coming in, each once, while a class marks - pfctl shows that a mark is set, not
         * which one (status.py's marked) - and the switch's queues: how many DSCPs have one, and what the
         * last Apply did, or why nothing is set there.
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
                "{{ lang._('connections with a mark set coming in, each once') }}"));
            const hw = data.hardware || {};
            const last = hw.last || {};
            if (hw.why_not) {
                $cards.append(card('', 'fa-sitemap', "{{ lang._('Switch queues') }}", "{{ lang._('none set') }}",
                    plain(switchNot[hw.why_not] || hw.why_not)));
            } else {
                const failed = last.status === 'failed' || last.status === 'refused';
                $cards.append(card(failed ? 'bad' : (hw.pending ? 'warn' : (last.status === 'applied' ? 'ok' : '')),
                    'fa-sitemap', "{{ lang._('Switch queues') }}",
                    fill("{{ lang._('%s of 2') }}", (hw.dscps || []).length),
                    failed ? "{{ lang._('last Apply not set:') }}" + ' ' + (last.said || '') :
                        hw.pending ? "{{ lang._('changed since the last Apply') }}" :
                        last.time ? "{{ lang._('set by Apply') }}" + ' ' + last.time : "{{ lang._('DSCPs with a queue of their own') }}"));
            }
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
                        return place(row.switch, row.switch_not);
                    }
                }
            }
        });

        /* Each rule of Firewall: Shaper, read and never written: what the switch takes of it, and what
           stays with the host, and why. The API escapes what it returns, as above. */
        $('#grid-shaper').UIBootgrid({
            search: '/api/trafficpriority/service/search_shaper',
            options: {
                selection: false,
                formatters: {
                    direction: function (column, row) {
                        return directions[row.direction] || row.direction;
                    },
                    taken: function (column, row) {
                        return shaperHardware(row);
                    },
                    stays: function (column, row) {
                        return shaperStays(row);
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
                $('#grid-shaper').bootgrid('reload');
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
            } else if (tab === '#shaper') {
                $('#grid-shaper').bootgrid('reload');
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
    <li><a data-toggle="tab" href="#shaper">{{ lang._('Firewall: Shaper') }}</a></li>
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
            {{ lang._('Matched now, Matched since reload, packets and bytes: what pf counted for the rules of each class. Every filter reload, an Apply among them, starts them again from 0 - packets and bytes too, unless the firewall keeps counters - while connections keep their mark; and a connection two classes match is counted under both, keeping the mark of the lower sequence. Marked now, above, counts each connection pf holds with a mark set coming in, once, whenever it opened, while a class marks. pfctl shows that a mark is set, not which one, so a normalization rule of yours setting any mark on connections coming in is counted too.') }}
        </div>
        <div id="tp-project" class="text-muted" style="display: none; padding: 0 15px 15px;">
            {{ lang._('os-xgs-npu is installed: it puts a marked IPv4 connection into hardware with its DSCP - measured with these rules on an XGS 3300 - and keeps a marked IPv6 connection with the host. A connection in hardware adds no more packets or bytes here.') }}
        </div>
        <div class="text-muted" style="padding: 0 15px 15px;">
            {{ lang._('Switch queue: on an XGS 3300 family appliance, every frame the coprocessor sends into its switch waits in queue 0, marked or not; os-xgs-npu picks out two DSCPs there and gives each a queue of its own, on every front port behind the switch at once - the first two in this list\'s order, IPv4. A class without a minimum is strict: it goes before everything else, and can take a whole port. One with a minimum is weighted: it keeps at least that part of a full port, and the rest keeps what is left. The front ports on the coprocessor\'s own MACs - F1 and F2 of the XGS 3300 - are not behind the switch. Measured on an XGS 3300: EF picked out into queue 7; not yet with these classes, nor a minimum held.') }}
        </div>
        <div id="tp-pf-alone" class="text-muted" style="display: none; padding: 0 15px 15px;">
            {{ lang._('pf alone marks connections here: without os-xgs-npu no hardware carries them.') }}
        </div>
    </div>
    <div id="shaper" class="tab-pane">
        <table id="grid-shaper" class="table table-condensed table-hover table-striped table-responsive">
            <thead>
                <tr>
                    <th data-column-id="uuid" data-type="string" data-identifier="true" data-visible="false">{{ lang._('ID') }}</th>
                    <th data-column-id="sequence" data-type="numeric" data-width="7em">{{ lang._('Sequence') }}</th>
                    <th data-column-id="description" data-type="string">{{ lang._('Rule') }}</th>
                    <th data-column-id="interface" data-type="string" data-width="8em">{{ lang._('Interface') }}</th>
                    <th data-column-id="direction" data-formatter="direction" data-type="string" data-width="7em">{{ lang._('Direction') }}</th>
                    <th data-column-id="target" data-type="string">{{ lang._('Pipe or queue') }}</th>
                    <th data-column-id="hardware" data-formatter="taken" data-type="string" data-sortable="false">{{ lang._('In the switch') }}</th>
                    <th data-column-id="host" data-formatter="stays" data-type="string" data-sortable="false">{{ lang._('With the host') }}</th>
                </tr>
            </thead>
            <tbody></tbody>
            <tfoot></tfoot>
        </table>
        <div class="text-muted" style="padding: 0 15px 15px;">
            {{ lang._('Firewall: Shaper is read here and never written, and it still shapes on the host: os-xgs-npu keeps every connection an enabled rule of it names with the host, off the hardware. With Follow Firewall: Shaper on (General), what the switch can do of a rule is done in its queues too, at Apply: a queue\'s weight, against the other queues of its pipe, as a part of every port for a DSCP a class here marks and has a queue for - a class\'s own minimum first, the parts together 100 percent at most - and a pipe\'s bandwidth as a front port\'s egress limit, where a rule sends everything leaving that port into the pipe, in the switch\'s steps of 1 Mbit/s up to 100 Mbit/s and 10 Mbit/s up to 1 Gbit/s. Not measured yet: a part or a limit from a rule here.') }}
        </div>
    </div>
    <div id="general" class="tab-pane">
        {{ partial("layout_partials/base_form", ['fields': generalForm, 'id': 'frm_general']) }}
    </div>
</div>

{{ partial('layout_partials/base_apply_button', {'data_endpoint': '/api/trafficpriority/service/reconfigure'}) }}
{{ partial("layout_partials/base_dialog", ['fields': classForm, 'id': formGridClass['edit_dialog_id'], 'label': lang._('Edit class')]) }}
{{ partial("OPNsense/TrafficPriority/credit") }}
