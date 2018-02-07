<%@ Page Language="C#" AutoEventWireup="true" CodeBehind="default.aspx.cs" Inherits="NPS_Web_App._default" %>

<!DOCTYPE html>

<html>
<head runat="server">
    <title>NPS MAB Editor</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <link rel="stylesheet" href="bootstrap.css" />
    <style type="text/css">
        body {
            background-color: #2F484F;
        }

        .title {
            font-weight: bold;
            font-size: xx-large;
        }

        .small {
            font-size: small;
        }

        label {
            font-weight: bold;
        }
    </style>
</head>
<body>
    <div class="container-fluid d-inline-flex justify-content-between align-items-center bg-secondary mb-4">
        <div class="col text-left">
            <span class="">U.S. Army</span>
        </div>
        <div class="col text-center">
            <span class="title">NPS MAB Editor</span>
        </div>
        <div class="col text-right">
            <button type="button" class="btn btn-light" data-toggle="modal" data-target="#helpModal">About / Help</button>
        </div>
    </div>
    <form id="form1" runat="server">
        <div id="main" class="container">
            <div class="row">
                <div class="container col-6">
                    <div class="card">
                        <div class="card-body">
                            <div class="form-group">
                                <div class="form-row">
                                    <input id="SearchBox" name="SearchBox" class="form-control" placeholder="Search..." />
                                </div>
                            </div>
                            <div class="form-group">
                                <label for="PolicyList">NPS Policy</label>
                                <select id="PolicyList" name="PolicyList" class="form-control"></select>
                            </div>

                            <div class="form-group">
                                <div class="form-row">
                                    <label for="MACBox">MAC Addresses</label>
                                </div>
                                <div class="form-row">
                                    <select id="MACBox" name="MACBox" class="form-control" size="10" multiple></select>
                                </div>
                            </div>
                            <div class="form-group form-row">
                                <div class="col">
                                    <button type="button" class="btn btn-warning form-control" data-toggle="modal" data-target="#deleteModal">Delete selected MACs</button>
                                </div>
                                <div class="col">
                                    <button type="button" class="btn btn-primary form-control" data-toggle="modal" data-target="#addModal">Add New MACs</button>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        <div class="modal fade" id="addModal" tabindex="-1" role="dialog" aria-labelledby="addModalLabel" aria-hidden="true">
            <div class="modal-dialog" role="document">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title" id="addModalLabel">Add MAC Addresses</h5>
                        <button type="button" class="close" data-dismiss="modal" aria-label="Close">
                            <span aria-hidden="true">&times;</span>
                        </button>
                    </div>
                    <div class="modal-body has-error">
                        <asp:TextBox runat="server" ID="MACInput" TextMode="MultiLine" CssClass="form-control" Rows="5"></asp:TextBox>
                        <small id="MACLimit" class="form-text text-danger">No more than 4000 total addresses per policy</small>
                        <small class="form-text text-muted">Input one MAC address per row</small>
                        <small id="MACFormat" class="form-text text-danger">Use '0F0F0F0F0F0F', '0F-0F-0F-0F-0F-0F','0F:0F:0F:0F:0F:0F', '0F0F.0F0F.0F0F', '000000.*', '00-00-00-.*', '00:00:00:.*', or '0000.00.*' format</small>
                    </div>
                    <div class="modal-footer">
                        <div class="container-fluid">
                            <div class="row">
                                <div class="col">
                                    <button type="button" class="form-control btn btn-dark" data-dismiss="modal">Cancel</button>
                                </div>
                                <div class="col">
                                    <asp:Button ID="ConfirmAddButton" runat="server" OnClick="AddMAC" Text="Add MACs" CssClass="form-control btn btn-success" />
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        <div class="modal fade" id="deleteModal" tabindex="-1" role="dialog" aria-labelledby="deleteModalLabel" aria-hidden="true">
            <div class="modal-dialog" role="document">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title" id="deleteModalLabel">Delete MAC Addresses</h5>
                        <button type="button" class="close" data-dismiss="modal" aria-label="Close">
                            <span aria-hidden="true">&times;</span>
                        </button>
                    </div>
                    <div class="modal-body alert" role="alert">
                        <div class="form-row">
                            Are you sure you want to delete these MACs?
                        </div>
                        <div id="deleteLabelContainer" class="form-row">
                            <label id="deleteLabel"></label>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <div class="container-fluid">
                            <div class="row">
                                <div class="col">
                                    <button type="button" class="form-control btn btn-dark" data-dismiss="modal">Cancel</button>
                                </div>
                                <div class="col">
                                    <asp:Button ID="ConfirmDeleteButton" runat="server" OnClick="DeleteMAC" Text="Delete MACs" CssClass="form-control btn btn-danger" />
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </form>

    <div class="modal fade" id="ConsentModal" tabindex="-1" role="dialog" aria-labelledby="consentModalLabel" aria-hidden="true">
        <div class="modal-dialog" role="document">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="consentModalLabel">USG Warning and Consent Banner</h5>
                    <button type="button" class="close" data-dismiss="modal" aria-label="Close">
                        <span aria-hidden="true">&times;</span>
                    </button>
                </div>
                <div class="modal-body">
                    <p>You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS (which includes any device attached to this IS), you consent to the following conditions:</p>
                    <ul class="small">
                        <li class="">The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.</li>
                        <li class="">At any time, the USG may inspect and seize data stored on this IS.</li>
                        <li class="">Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG authorized purpose.</li>
                        <li class="">This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.</li>
                        <li class="">Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.</li>
                    </ul>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-dismiss="modal">Close</button>
                </div>
            </div>
        </div>
    </div>

    <div class="modal fade" id="helpModal" tabindex="-1" role="dialog" aria-labelledby="helpModalLabel" aria-hidden="true">
        <div class="modal-dialog modal-lg" role="document">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="helpModalLabel">About this application</h5>
                    <button type="button" class="close" data-dismiss="modal" aria-label="Close">
                        <span aria-hidden="true">&times;</span>
                    </button>
                </div>
                <div class="modal-body">
                    This application was created by CPT John Pavlik, 93d Signal Brigade for use by the US Army. 
                    <br />
                    <br />
                    It is designed to manage MAC Address Bypass policies in Microsoft Network Policy Servers.<br />
                    <br />
                    If you need assistance or have a bug report, then please contact either your local Network Enterprise Center or <a href="mailto:john.a.pavlik.mil@mail.mil">john.a.pavlik.mil@mail.mil</a>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-dismiss="modal">Close</button>
                </div>
            </div>
        </div>
    </div>
    <script src="jquery-3.2.1.slim.min.js"></script>
    <script src="bootstrap.bundle.min.js"></script>

    <script>var mac_data = <%= GetJSONPolicyMacs %>;</script>
    <script src="script.js"></script>
</body>
</html>
