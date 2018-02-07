﻿
$.fn.extend({
    disable: function (state) {
        return this.each(function () {
            let $this = $(this);
            if ($this.is('input, button, textarea, select'))
                this.disabled = state;
            else
                $this.toggleClass('disabled', state);
        });
    }
});

$.fn.multiline = function (text) {
    this.text(text);
    this.html(this.html().replace(/\n/g, '<br/>'));
    return this;
}

class MACField {
    constructor(text, value) {
        this.text = text;
        this.value = value;
    }
}

function ValidateAdd() {
    let valid = false;
    let macs = $('#MACInput').val().split(/\n/);
    let policy = $('#PolicyList :selected').text()
    let underLimit = macs.length + full_mac_list[policy].length <= 4000;

    if (!underLimit) {
        $('#MACLimit').show();
        valid = false;
    } else {
        $('#MACLimit').hide();
        macs.forEach(function (e) {
            e = $.trim(e)
            if (e.match(/^[a-fA-F0-9]{12}$/)) { valid = true; }
            else if (e.match(/^[a-fA-F0-9]{2}-[a-fA-F0-9]{2}-[a-fA-F0-9]{2}-[a-fA-F0-9]{2}-[a-fA-F0-9]{2}-[a-fA-F0-9]{2}$/)) { valid = true; }
            else if (e.match(/^[a-fA-F0-9]{6}\.\*$/)) { valid = true; }
            else if (e.match(/^[a-fA-F0-9]{2}-[a-fA-F0-9]{2}-[a-fA-F0-9]{2}-\.\*$/)) { valid = true; }
            else if (e.match(/^[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:\.\*$/)) { valid = true; }
            else if (e.match(/^[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}$/)) { valid = true; }
            else if (e.match(/^[a-fA-F0-9]{4}\.[a-fA-F0-9]{2}\.\*$/)) { valid = true; }
            else if (e.match(/^[a-fA-F0-9]{4}\.[a-fA-F0-9]{4}\.[a-fA-F0-9]{4}$/)) { valid = true; }
            else if (e.match(/^\s*$/)) { ; }
            else {
                valid = false;
            }
            if (!valid) {
                $('#MACFormat').show();
            } else {
                $('#MACFormat').hide();
            }
        });
    }
    $('#MACInput').toggleClass('is-invalid', !valid);
    return valid;
}

function FilterItems(query, items) {
    let queryfiltered = query.toLowerCase();
    return items.filter(function (el) {
        return el.value.match(queryfiltered);
    })
}

function buildOptions(data) {
    let html = new Array();
    for (let i = 0, len = data.length; i < len; ++i) {
        html.push("<option value=\"");
        html.push(data[i].value);
        html.push("\">");
        html.push(data[i].text);
        html.push("</option>");
    }
    $('#MACBox').html(html.join(''));
}

function searchFunction() {
    let macbox = $('#MACBox');
    macbox.empty();
    let searchString = $.trim($(this).val().replace(/\-/g, ''));
    let policies = []
    for (let p of Object.keys(full_mac_list)) {
        let macs = FilterItems(searchString, full_mac_list[p]);
        if (searchString.length == 0 || macs.length > 0) {
            policies.push(p);
        }
    }

    let policy = $('#PolicyList :selected').text()
    BuildPoliciesList(policies.sort(), policy);
    policy = $('#PolicyList :selected').text()
    if (policies.length > 0) {
        if (searchString.length > 0) {
            buildOptions(FilterItems(searchString, full_mac_list[policy]));
        } else {
            buildOptions(full_mac_list[policy]);
        }
    } else {
        buildOptions([]);
    }
}

function ChangePolicy() {
    $('#SearchBox').trigger('input');
}

function BuildPoliciesList(policyArray, policy) {
    let policies = new Array();
    for (let key of policyArray) {
        policies.push("<option>");
        policies.push(key);
        policies.push("</option>");
    }
    $('#PolicyList').html(policies.join(''));
    if ($.inArray(policy, policyArray) > -1) {
        $('#PolicyList').val(policy).prop('selected', true);
    }
}

$(document).ready(function () {

    $('#MACFormat').hide();
    $('#MACLimit').hide();

    full_mac_list = {};
    for (let key of Object.keys(mac_data).sort()) {
        full_mac_list[key] = [];
        for (let mac of mac_data[key].sort()) {
            full_mac_list[key].push(new MACField(mac, mac.replace(/\-/g, '').toLowerCase()));
        }
    }

    BuildPoliciesList(Object.keys(mac_data).sort());
    $('#PolicyList').on('change', ChangePolicy);

    $('#deleteModal').on('show.bs.modal', function (e) {
        let text = "";
        $('#MACBox > option').each(function () {
            if (this.selected) {
                text += this.text + '\n';
            }
        });
        if (text === "" || text === "NO MAC ADDRESSES FOUND\n") {
            text = "No MAC addresses selected.  Please choose at least one.";
            $('#ConfirmDeleteButton').disable(true);
            $('#deleteLabelContainer').addClass('alert-warning');
            $('#deleteModal').modal('handleUpdate');
        } else {
            $('#ConfirmDeleteButton').disable(false);
            $('#deleteLabelContainer').removeClass('alert-warning');
        }
        $('#deleteLabel').multiline(text);
    })

    $('#ConfirmAddButton').disable(true);
    $('#MACInput').keyup(function () {
        $('#ConfirmAddButton').disable(!ValidateAdd());
    });

    $('#SearchBox').on('input', searchFunction);
    $('#PolicyList').trigger('change');
})

window.onload = function () {
    var visited = sessionStorage['visited'];
    if (!visited) {
        $('#ConsentModal').modal('show')
        sessionStorage['visited'] = true;
    }
}