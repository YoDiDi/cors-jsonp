package burp;

import java.awt.*;
import java.io.PrintWriter;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import javafx.scene.layout.Pane;
import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;

public class BurpExtender extends AbstractTableModel implements IBurpExtender, IScannerCheck, ITab, IMessageEditorController {
    private IBurpExtenderCallbacks callbacks;

    private IExtensionHelpers helpers;

    private PrintWriter stdout;

    private JSplitPane mjSplitPane;

    private List<TablesData> Udatas = new ArrayList<>();

    private IMessageEditor HRequestTextEditor;

    private IMessageEditor HResponseTextEditor;

    private IHttpRequestResponse currentlyDisplayedItem;

    private URLTable Utable;

    private JScrollPane UscrollPane;

    private JSplitPane HjSplitPane;

    private JSplitPane HjSplitPane2;

    private JPanel mjPane;

    private JTabbedPane Ltable;

    private JTabbedPane Rtable;

    private JTextArea textArea1;

    private JTextArea textArea2;

    private JPanel panel1;

    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        callbacks.setExtensionName("corsjsonp");
        this.stdout.println("===========================");
        this.stdout.println("[+]   load successful!     ");
        this.stdout.println("[+]   corsjsonp v0.1       ");
        this.stdout.println("[+]   code by yodidi     ");
        this.stdout.println("[+]  ");
        this.stdout.println("===========================");
        SwingUtilities.invokeLater(new Runnable() {
            public void run() {
                BurpExtender.this.textArea1 = new JTextArea("");
                BurpExtender.this.textArea2 = new JTextArea("");
                BurpExtender.this.mjSplitPane = new JSplitPane(0); //上下
                BurpExtender.this.Utable = new BurpExtender.URLTable(BurpExtender.this);
                BurpExtender.this.UscrollPane = new JScrollPane(BurpExtender.this.Utable);
                BurpExtender.this.HjSplitPane = new JSplitPane();
                BurpExtender.this.HjSplitPane2 = new JSplitPane();
                BurpExtender.this.HjSplitPane.setDividerLocation(650);
                BurpExtender.this.Ltable = new JTabbedPane();
                BurpExtender.this.HRequestTextEditor = BurpExtender.this.callbacks.createMessageEditor(BurpExtender.this, false);
                BurpExtender.this.Ltable.addTab("Request", BurpExtender.this.HRequestTextEditor.getComponent());
                BurpExtender.this.Rtable = new JTabbedPane();
                BurpExtender.this.HResponseTextEditor = BurpExtender.this.callbacks.createMessageEditor(BurpExtender.this, false);
                BurpExtender.this.Rtable.addTab("Response", BurpExtender.this.HResponseTextEditor.getComponent());

                BurpExtender.this.Rtable.add("cors关键字", BurpExtender.this.textArea1);
                BurpExtender.this.Rtable.add("jsonp关键字", BurpExtender.this.textArea2);
                BurpExtender.this.textArea1.setText("*");
                BurpExtender.this.textArea2.setText("*");
                BurpExtender.this.HjSplitPane.add(BurpExtender.this.Ltable, "left"); // request窗体
                BurpExtender.this.HjSplitPane.add(BurpExtender.this.Rtable, "right"); // response窗体
                BurpExtender.this.mjSplitPane.add(BurpExtender.this.UscrollPane, "left"); // 结果集
                BurpExtender.this.mjSplitPane.add(BurpExtender.this.HjSplitPane, "right"); // request response一起


                BurpExtender.this.callbacks.customizeUiComponent(BurpExtender.this.mjSplitPane);
                BurpExtender.this.callbacks.addSuiteTab(BurpExtender.this);
            }
        });
        callbacks.registerScannerCheck(this);
    }

    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {

        String corswords = BurpExtender.this.textArea1.getText(); // 关键字读取
        String jsonpwords = BurpExtender.this.textArea2.getText(); // 关键字读取

        byte[] request = baseRequestResponse.getRequest();
        URL url = this.helpers.analyzeRequest(baseRequestResponse).getUrl();
        IRequestInfo analyzedIRequestInfo = this.helpers.analyzeRequest(request);

        List<String> request_header = analyzedIRequestInfo.getHeaders(); // 获取请求头
        // 循环获取参数，判断类型，进行加密处理后，再构造新的参数，合并到新的请求包中。

        String firstrequest_header = request_header.get(0); //第一行请求

        if(firstrequest_header.contains(".png") || firstrequest_header.contains(".js") || firstrequest_header.contains(".jpg") || firstrequest_header.contains(".jpeg") || firstrequest_header.contains(".svg")  || firstrequest_header.contains(".mp4") || firstrequest_header.contains(".css") || firstrequest_header.contains(".mp3")        ){
            return null;
        }
        else {

            String[] firstheaders = firstrequest_header.split(" ");
            if(firstheaders[1].contains("callback="))
                firstheaders[1] = firstheaders[1].replace("callback=","callback=testjsonp"); // 原始请求含有callback，直接替换
            else {
                if (firstheaders[1].endsWith("?"))
                    firstheaders[1] = firstheaders[1] + "callback=testjsonp"; // 含有参数的项，?结尾
                else if (firstheaders[1].contains("?") && !firstheaders[1].endsWith("?"))
                    firstheaders[1] = firstheaders[1] + "&callback=testjsonp"; // 含有参数的项，含有?且不是?结尾
                else
                    firstheaders[1] = firstheaders[1] + "?callback=testjsonp"; // 含有参数的项，直接参数后面加callback参数
            }

            request_header.set(0,firstheaders[0] + " " + firstheaders[1] + " " + firstheaders[2]);
            // 去除源请求包里的Origin参数
            /*****************删除header**********************/
            request_header.removeIf(header -> header.startsWith("Origin"));
            request_header.add("Origin: baitdu.com"); // 请求头增加

            /*****************获取body 方法一**********************/
            int bodyOffset = analyzedIRequestInfo.getBodyOffset();
            byte[] byte_Request = baseRequestResponse.getRequest();

            String request2 = new String(byte_Request); //byte[] to String
            String body = request2.substring(bodyOffset);
            byte[] request_bodys = body.getBytes();  //String to byte[]

            String reqMethod = this.helpers.analyzeRequest(baseRequestResponse).getMethod();
            //        stdout.println(newParameter);
            byte[] newRequest = this.helpers.buildHttpMessage(request_header, request_bodys);
            IHttpService httpService = baseRequestResponse.getHttpService();
            IHttpRequestResponse newIHttpRequestResponse = this.callbacks.makeHttpRequest(httpService, newRequest);
            byte[] response = newIHttpRequestResponse.getResponse();
            IResponseInfo analyzedResponse = helpers.analyzeResponse(response);

            /****************获取响应包的响应体******************/
            String response1 = new String(response); //byte[] to String



            //        stdout.println(this.helpers.analyzeResponse(response).getHeaders());
            int IsCorsControl = 0;
            int IsCorstrue = 0;
            int IsJsonp = 0;
            for (String cookies : this.helpers.analyzeResponse(response).getHeaders()) {
                //            stdout.println(cookies);
                if (cookies.equals("Access-Control-Allow-Origin: baitdu.com") ) {
                    IsCorsControl++;
                }
                if (cookies.equals("Access-Control-Allow-Origin: *") ) {
                    IsCorsControl++;
                }

                if (cookies.equals("Access-Control-Allow-Credentials: true") ) {
                    IsCorstrue++;
                }

            }
            if (response1.contains("testjsonp"))
                IsJsonp++;
            if (IsCorsControl > 0 && IsCorstrue > 0 ) {
                String[] corswords_lists = corswords.split("\n");
                for (String corsword:corswords_lists) {
                    if (corsword.equals("*"))
                        corsword = "";
                    if (response1.contains(corsword) )
                    synchronized (this.Udatas) {
                        int row = this.Udatas.size();
                        this.Udatas.add(new TablesData(row, reqMethod, url.toString(), this.helpers.analyzeResponse(response).getStatusCode() + "", "Cors vuln  " + corsword, newIHttpRequestResponse, httpService.getHost(), httpService.getPort()));
                        fireTableRowsInserted(row, row);
                        List<IScanIssue> issues = new ArrayList<>(1);
                        return issues;
                    }
                }
            }
            if (IsJsonp > 0 ) {
                String[] jsonpwords_lists = jsonpwords.split("\n");
                for (String jsonpword:jsonpwords_lists) {
                    if (response1.contains(jsonpword))
                        synchronized (this.Udatas) {
                            int row = this.Udatas.size();
                            this.Udatas.add(new TablesData(row, reqMethod, url.toString(), this.helpers.analyzeResponse(response).getStatusCode() + "", "Jsonp maybe vuln  " + jsonpword, newIHttpRequestResponse, httpService.getHost(), httpService.getPort()));
                            fireTableRowsInserted(row, row);
                            List<IScanIssue> issues = new ArrayList<>(1);
                            return issues;
                        }
                }
            }

        }
            return null;

    }


    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        return null;
    }

    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        if (existingIssue.getIssueName().equals(newIssue.getIssueName()))
            return -1;
        return 0;
    }

    boolean checUrl(String host, int port) {
        for (TablesData d : this.Udatas) {
            if (d.host.equals(host) && d.port == port)
                return false;
        }
        return true;
    }

    public IHttpService getHttpService() {
        return this.currentlyDisplayedItem.getHttpService();
    }

    public byte[] getRequest() {
        return this.currentlyDisplayedItem.getRequest();
    }

    public byte[] getResponse() {
        return this.currentlyDisplayedItem.getResponse();
    }

    public String getTabCaption() {
        return "corsjsonp";
    }

    public Component getUiComponent() {
        return this.mjSplitPane;
    }

    public int getRowCount() {
        return this.Udatas.size();
    }

    public int getColumnCount() {
        return 5;
    }

    public String getColumnName(int columnIndex) {
        switch (columnIndex) {
            case 0:
                return "#";
            case 1:
                return "Method";
            case 2:
                return "URL";
            case 3:
                return "Status";
            case 4:
                return "Issue";
        }
        return null;
    }

    public Object getValueAt(int rowIndex, int columnIndex) {
        TablesData datas = this.Udatas.get(rowIndex);
        switch (columnIndex) {
            case 0:
                return Integer.valueOf(datas.Id);
            case 1:
                return datas.Method;
            case 2:
                return datas.URL;
            case 3:
                return datas.Status;
            case 4:
                return datas.issue;
        }
        return null;
    }

    public class URLTable extends JTable {
        public URLTable(TableModel tableModel) {
            super(tableModel);
        }

        public void changeSelection(int row, int col, boolean toggle, boolean extend) {
            BurpExtender.TablesData dataEntry = BurpExtender.this.Udatas.get(convertRowIndexToModel(row));
            BurpExtender.this.HRequestTextEditor.setMessage(dataEntry.requestResponse.getRequest(), true);
            BurpExtender.this.HResponseTextEditor.setMessage(dataEntry.requestResponse.getResponse(), false);
            BurpExtender.this.currentlyDisplayedItem = dataEntry.requestResponse;
            super.changeSelection(row, col, toggle, extend);
        }
    }

    public static class TablesData {
        final int Id;

        final String Method;

        final String URL;

        final String Status;

        final String issue;

        final IHttpRequestResponse requestResponse;

        final String host;

        final int port;

        public TablesData(int id, String method, String url, String status, String issue, IHttpRequestResponse requestResponse, String host, int port) {
            this.Id = id;
            this.Method = method;
            this.URL = url;
            this.Status = status;
            this.issue = issue;
            this.requestResponse = requestResponse;
            this.host = host;
            this.port = port;
        }
    }
}
