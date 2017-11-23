var macList = [];

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

function ValidateAdd() {
    let valid = false;
    let macs = $('#MACInput').val().split(/\n/);
    let underLimit = macs.length + macList.length <= 4000;
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
            else if (e.match(/^\s*$/)) {; }
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
    let queryfiltered = query.toLowerCase().replace(/\-/g, '');
    return items.filter(function (el) {
        return el.value.match(queryfiltered);
    })
}

$(document).ready(function () {
    
    $('#MACFormat').hide();
    $('#MACLimit').hide();

    $('#MACBox > option').each(function () {
        macList.push(this);
    });

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
    $('#SearchBox').keyup(function () {
        let macbox = $('#MACBox');
        macbox.empty();
        let searchString = $.trim($(this).val().replace(/\-/g, ''));
        if (searchString.length > 0) {
            buildOptions(FilterItems(searchString, macList));
        } else {
            buildOptions(macList);
        }
    })

})

window.onload = function () {
    var visited = sessionStorage['visited'];
    if (!visited) {
        $('#ConsentModal').modal('show')
        sessionStorage['visited'] = true;
    }
}